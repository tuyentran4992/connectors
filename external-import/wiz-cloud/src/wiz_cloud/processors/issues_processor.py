"""Processor turning Wiz Threat Detection issues into OpenCTI Incidents.

Each issue becomes an Incident, and the cloud resource it was raised on
becomes a System linked with a targets relationship. When vulnerability
import is enabled, the findings of that resource are fetched while the issue
is converted and travel in the same bundle, so an issue and its
vulnerabilities are never committed apart.
"""

from __future__ import annotations
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from connectors_sdk.models import (
    ExternalReference,
    Incident,
    OrganizationAuthor,
    Relationship,
    System,
    TLPMarking,
    Vulnerability,
)
from connectors_sdk import BaseDataProcessor
from connectors_sdk.models.enums import (
    CvssSeverity,
    IncidentSeverity,
    IncidentType,
    RelationshipType,
)
from wiz_client.client_api import WizApiClient
from wiz_client.models import WizEntitySnapshot, WizIssue

if TYPE_CHECKING:
    from wiz_client.models import WizIssue, WizVulnerabilityFinding
    from wiz_cloud.settings import ConnectorSettings
    from wiz_cloud.state import WizConnectorState

# Wiz Severity enum to SDK IncidentSeverity. INFORMATIONAL has no OpenCTI
# equivalent and maps to LOW.
_SEVERITY = {
    "CRITICAL": IncidentSeverity.CRITICAL,
    "HIGH": IncidentSeverity.HIGH,
    "MEDIUM": IncidentSeverity.MEDIUM,
    "LOW": IncidentSeverity.LOW,
    "INFORMATIONAL": IncidentSeverity.LOW,
}


class WizIssuesProcessor(BaseDataProcessor):
    settings: ConnectorSettings
    state: WizConnectorState

    def post_init(self) -> None:
        """Build the Wiz client and the objects shared by every bundle.

        Called by the SDK once dependencies are injected, so settings are
        available here but not in __init__.
        """
        self._config = self.settings.wiz_cloud
        self._client = WizApiClient(
            base_url=str(self._config.api_url),
            auth_url=str(self._config.auth_url),
            client_id=self._config.client_id.get_secret_value(),
            client_secret=self._config.client_secret.get_secret_value(),
            logger=self.logger,
            timeout=60,
            max_retries=3,
            backoff_factor=2.0,
        )

        self._author = OrganizationAuthor(name="Wiz")
        self._marking = TLPMarking(level=self._config.marking)

        self._issue_converter = IssueConverter(
            author=self._author,
            marking=self._marking,
        )
        self._vulnerability_converter = VulnerabilityConverter(
            author=self._author,
            marking=self._marking,
        )

    def _paginate_issues(self, since: datetime) -> Iterator[list[WizIssue]]:
        return self._client.paginate_issues(
            first=self._config.page_size,
            after=None,
            severity=self._config.issue_severity,
            status=self._config.issue_status,
            created_after=since,
        )

    def _paginate_vulnerabilities(
        self, issue: WizIssue
    ) -> Iterator[list[WizVulnerabilityFinding]]:
        if not issue.entity_snapshot:
            return iter([])

        return self._client.paginate_vulnerabilities(
            first=self._config.page_size,
            after=None,
            severity=self._config.vulnerability_severity,
            status=self._config.vulnerability_status,
            has_exploit=self._config.vulnerability_has_exploit,
            asset_id=issue.entity_snapshot.id,
        )

    def collect(self) -> Iterator[list[WizIssue]]:
        """Fetch Threat Detection issues created since the last run.

        The lower bound is the stored cursor, or now minus the configured
        since window on a first run.

        Yields:
            Lists of raw issue dicts, one per API page.
        """
        since = self.state.issues_last_created_at or (
            datetime.now(tz=timezone.utc) - self._config.since
        )

        self.work_name = f"Wiz Cloud issues import since {since:%Y-%m-%d %H:%M}"

        self.logger.info(
            "[WIZ-CLOUD] Collecting issues",
            {
                "since": since.isoformat(),
                "severity": self._config.issue_severity,
                "status": self._config.issue_status,
            },
        )

        for issues_page in self._paginate_issues(since=since):
            results = []

            for issue in issues_page:
                result = {"issue": issue, "vulnerabilities": []}

                if self._config.import_vulnerabilities:
                    for issue in issues_page:
                        if issue.entity_snapshot:
                            for vulnerabilities_page in self._paginate_vulnerabilities(
                                issue=issue
                            ):
                                result["vulnerabilities"].extend(vulnerabilities_page)
                results.append(result)

            yield results

    def transform(self, data: Iterator[list[dict]]) -> Iterator[list]:
        """Convert raw issue pages into bundle objects.

        Unparseable issues are logged and skipped rather than failing the run.

        When vulnerability import is enabled, each issue is emitted as its own
        bundle carrying the vulnerabilities of its resource, so the two are
        committed together. Otherwise one bundle per page is emitted, as
        before.

        Args:
            data: Pages of raw issue dicts yielded by collect().

        Yields:
            Lists of SDK objects: one bundle per issue when vulnerabilities
            are imported, one bundle per non-empty page otherwise.
        """
        # Run-scoped caches: the same entitySnapshot backs many issues, and
        # author/marking must be sent once, not once per page.
        systems_cache: dict[str, System] = {}
        issues_converted = 0
        vulnerabilities_converted = 0
        bundles_sent = 0
        shared_sent = False
        max_created = self.state.issues_last_created_at

        for results in data:
            page_objects: list = []

            for result in results:
                issue = result["issue"]

                issue_objects = self._issue_converter.convert_issue(
                    issue, systems_cache
                )
                page_objects.extend(issue_objects)
                issues_converted += 1

                if max_created is None or issue.created_at > max_created:
                    max_created = issue.created_at

                if self._config.import_vulnerabilities:
                    vulnerabilities = result["vulnerabilities"]

                    for vulnerability in vulnerabilities:
                        if not vulnerability.name:
                            self.logger.warning(
                                "[WIZ-CLOUD] Skipping finding without a CVE id",
                                {"id": vulnerability.id},
                            )
                            continue

                        vulnerability_objects = (
                            self._vulnerability_converter.convert_vulnerability(
                                issue.entity_snapshot.id,
                                systems_cache[issue.entity_snapshot.id],
                            )
                        )
                        page_objects.extend(vulnerability_objects)
                        vulnerabilities_converted += 1

                self.logger.info(
                    "[WIZ-CLOUD] Sending an incident with its vulnerabilities",
                    {
                        "issue_id": issue.id,
                        "asset": (
                            issue.entity_snapshot.name
                            if issue.entity_snapshot
                            else None
                        ),
                        # Zero when the asset was already scanned this run:
                        # its vulnerabilities went out with an earlier issue.
                        "vulnerabilities": vulnerabilities,
                    },
                )

            if page_objects:
                yield self._with_shared(page_objects, shared_sent)
                shared_sent = True
                bundles_sent += 1

        if issues_converted == 0:
            self.logger.info(
                "[WIZ-CLOUD] Nothing to ingest, no new issue since the last run",
                (
                    {"since": self.state.issues_last_created_at}
                    if self.state.issues_last_created_at
                    else {}
                ),
            )
        else:
            self.logger.info(
                "[WIZ-CLOUD] Import finished",
                {
                    "incidents": issues_converted,
                    "vulnerabilities": vulnerabilities_converted,
                    "bundles": bundles_sent,
                },
            )

        self._advance_cursor(max_created)

    def _with_shared(self, objects: list, already_sent: bool) -> list:
        """Prepend the author and marking to the first bundle carrying data.

        Args:
            objects: The bundle objects.
            already_sent: Whether a previous bundle carried them.

        Returns:
            The bundle, with author and marking in front when they are still
            owed. They never travel in a bundle of their own.
        """
        if already_sent:
            return objects
        return [self._author, self._marking, *objects]

    def _advance_cursor(self, max_created: datetime | None) -> None:
        """Store the newest issue createdAt, unless vulnerabilities failed.

        A failed fetch is not fatal, but the issues it belongs to must not be
        marked as done: leaving the cursor where it is replays the whole
        window on the next run. Replaying is harmless because every object
        carries a deterministic id, whereas advancing would drop those
        vulnerabilities for good.

        The connector persists the state only after all processors succeed.

        Args:
            max_created: The newest createdAt converted this run, if any.
        """
        if max_created is None:
            return

        # ! Disagree -> should be fatal for the same reason not beeing able to fecth issues should be fatal
        # failures = self._vulnerabilities.failures if self._vulnerabilities else 0
        # if failures:
        #     self.logger.warning(
        #         "[WIZ-CLOUD] Holding the issues cursor back after vulnerability "
        #         "failures, the window will be imported again on the next run",
        #         {"failed_assets": failures},
        #     )
        #     return

        self.state.issues_last_created_at = max_created


class IssueConverter:
    def __init__(self, author: OrganizationAuthor, marking: TLPMarking) -> None:
        self._author = author
        self._marking = marking

    def convert_issue(self, issue: WizIssue, systems_cache: dict[str, System]) -> list:
        """Convert one Wiz issue into its bundle objects.

        Args:
            issue: Parsed Wiz issue.
            systems_cache: Systems already built during this run, keyed by
                entitySnapshot id, so a resource shared by several issues is
                emitted once and targeted many times.

        Returns:
            A list holding the Incident, plus the System and the targets
            Relationship when the issue carries an entity snapshot. A list is
            returned so further entities can be appended without changing the
            signature.
        """
        objects: list = []

        incident = Incident(
            name=self._incident_name(issue),
            description=issue.description or None,  # "" observed in payloads
            incident_type=IncidentType.ALERT,
            severity=_SEVERITY.get(issue.severity, IncidentSeverity.LOW),
            source="Wiz",
            # Event timestamps are the real activity window; createdAt is
            # only when Wiz noticed.
            first_seen=issue.first_event_at or issue.created_at,
            last_seen=issue.last_event_at or issue.updated_at,
            labels=self._labels(issue),
            external_references=self._issue_references(issue),
            author=self._author,
            markings=[self._marking],
        )
        objects.append(incident)

        if issue.entity_snapshot is not None:
            system, is_new = self._system_for(issue.entity_snapshot, systems_cache)
            if is_new:
                objects.append(system)
            objects.append(
                Relationship(
                    type=RelationshipType.TARGETS,
                    source=incident,
                    target=system,
                    author=self._author,
                    markings=[self._marking],
                )
            )

        return objects

    def _incident_name(self, issue: WizIssue) -> str:
        # sourceRule.name + the Wiz issue id. Rule name alone repeats across
        # hundreds of issues and description is rule-generic prose, so the id
        # is what keeps each incident name unambiguous.
        name = issue.rule_name or ""
        return f"{name} - Wiz issue {issue.id}" if name else f"Wiz issue {issue.id}"

    def _labels(self, issue: WizIssue) -> list[str]:
        # No "wiz" label: the incident is already created-by the Wiz author
        # and carries a Wiz external reference, so it would only add a label
        # every analyst has to filter out.
        labels = [issue.type.lower().replace("_", "-"), issue.status.lower()]
        if issue.rule_name:
            labels.append(issue.rule_name)
        return labels

    def _issue_references(self, issue: WizIssue) -> list[ExternalReference]:
        references = []
        if issue.url:
            references.append(
                ExternalReference(
                    source_name="Wiz",
                    url=issue.url,  # taken from the API, never rebuilt
                    external_id=issue.id,
                    description="Wiz issue",
                )
            )
        return references

    def _system_for(
        self, snapshot: WizEntitySnapshot, cache: dict[str, System]
    ) -> tuple[System, bool]:
        if snapshot.id in cache:
            return cache[snapshot.id], False

        description_parts = [
            part
            for part in (
                snapshot.type,
                snapshot.cloud_platform,
                snapshot.region or None,  # "" observed in payloads
                snapshot.provider_id or None,
            )
            if part
        ]
        references = []
        if snapshot.external_id:
            references.append(
                ExternalReference(
                    source_name="Wiz",
                    external_id=snapshot.external_id,
                    description="Cloud provider resource identifier",
                    # cloudProviderURL is usually "" in practice; guard on
                    # falsiness, not None.
                    url=snapshot.cloud_provider_url or None,
                )
            )

        system = System(
            name=snapshot.name,
            description=" | ".join(description_parts) or None,
            labels=[f"{key}={value}" for key, value in snapshot.tags.items()],
            external_references=references,
            author=self._author,
            markings=[self._marking],
        )
        cache[snapshot.id] = system
        return system, True


class VulnerabilityConverter:
    def __init__(self, author: OrganizationAuthor, marking: TLPMarking) -> None:
        self._author = author
        self._marking = marking

    def convert_vulnerability(
        self, finding: WizVulnerabilityFinding, system: System
    ) -> list:
        """Convert one finding into its bundle objects.

        Args:
            finding: Parsed Wiz vulnerability finding.
            system: The System carrying the vulnerability.

        Returns:
            The Vulnerability and its has Relationship, or an empty list when
            the finding carries no CVE id and so cannot be keyed.
        """
        vulnerability = self._vulnerability(finding)
        return [
            vulnerability,
            Relationship(
                type=RelationshipType.HAS,
                source=system,
                target=vulnerability,
                description=(
                    f"Wiz finding {finding.id}, "
                    f"severity {finding.severity}, status {finding.status}"
                ),
                start_time=finding.first_detected_at,
                # stop_time is left unset on purpose: generate_id() hashes it,
                # so lastDetectedAt would mint a new relationship every run.
                author=self._author,
                markings=[self._marking],
            ),
        ]

    def _vulnerability(self, finding: WizVulnerabilityFinding) -> Vulnerability:
        cvss_v2 = finding.cvss_v2
        cvss_v3 = finding.cvss_v3
        cvss_v4 = finding.cvss_v4
        return Vulnerability(
            # The OpenCTI id derives from the name alone, so it must be the
            # CVE id.
            name=finding.name,
            # CVEDescription is the CVE text; description is finding-specific
            # prose that would differ per asset and fight itself on merge.
            description=finding.cve_description or finding.description or None,
            # Wiz score is a CVSS base score, not the OpenCTI 0-100 score.
            cvss_v3_base_score=finding.score,
            cvss_v3_base_severity=self._cvss_severity(finding.cvss_severity),
            cvss_v3_attack_vector=cvss_v3.attack_vector if cvss_v3 else None,
            cvss_v3_attack_complexity=cvss_v3.attack_complexity if cvss_v3 else None,
            cvss_v3_privileges_required=(
                cvss_v3.privileges_required if cvss_v3 else None
            ),
            cvss_v3_user_interaction=(
                self._user_interaction(cvss_v3.user_interaction_required)
                if cvss_v3
                else None
            ),
            cvss_v3_confidentiality_impact=(
                cvss_v3.confidentiality_impact if cvss_v3 else None
            ),
            cvss_v3_integrity_impact=cvss_v3.integrity_impact if cvss_v3 else None,
            cvss_v3_availability_impact=(
                cvss_v3.availability_impact if cvss_v3 else None
            ),
            cvss_v3_scope=cvss_v3.scope if cvss_v3 else None,
            cvss_v3_exploit_code_maturity=(
                cvss_v3.exploit_code_maturity if cvss_v3 else None
            ),
            cvss_v2_access_vector=cvss_v2.attack_vector if cvss_v2 else None,
            cvss_v2_access_complexity=cvss_v2.attack_complexity if cvss_v2 else None,
            cvss_v2_confidentiality_impact=(
                cvss_v2.confidentiality_impact if cvss_v2 else None
            ),
            cvss_v2_integrity_impact=cvss_v2.integrity_impact if cvss_v2 else None,
            cvss_v2_availability_impact=(
                cvss_v2.availability_impact if cvss_v2 else None
            ),
            cvss_v4_attack_vector=cvss_v4.attack_vector if cvss_v4 else None,
            cvss_v4_attack_complexity=cvss_v4.attack_complexity if cvss_v4 else None,
            cvss_v4_attack_requirements=(
                cvss_v4.attack_requirements if cvss_v4 else None
            ),
            cvss_v4_privileges_required=(
                cvss_v4.privileges_required if cvss_v4 else None
            ),
            cvss_v4_user_interaction=cvss_v4.user_interaction if cvss_v4 else None,
            epss_score=self._ratio(finding.epss_probability),
            epss_percentile=self._ratio(finding.epss_percentile),
            is_cisa_kev=finding.has_cisa_kev_exploit,
            external_references=self._finding_references(finding),
            author=self._author,
            markings=[self._marking],
        )

    def _ratio(self, percentage: float | None) -> float | None:
        """Convert a Wiz percentage into the 0-1 ratio OpenCTI expects.

        Args:
            percentage: A percentage such as 72.4, or None.

        Returns:
            The value divided by 100, or None. Values outside 0-100 are dropped
            rather than rejected by the model.
        """
        if percentage is None or not 0 <= percentage <= 100:
            return None
        return round(percentage / 100, 6)

    def _user_interaction(self, required: bool | None) -> str | None:
        """Convert the Wiz boolean into the CVSS user-interaction string.

        Args:
            required: Whether user interaction is required, or None.

        Returns:
            "REQUIRED", "NONE", or None when unknown.
        """
        if required is None:
            return None
        return "REQUIRED" if required else "NONE"

    def _cvss_severity(self, severity: str | None) -> CvssSeverity | None:
        """Convert a Wiz CVSS severity into the SDK enum.

        Args:
            severity: A Wiz severity such as "HIGH", or None.

        Returns:
            The matching CvssSeverity, or None when it is unknown.
        """
        if not severity:
            return None
        try:
            return CvssSeverity(severity.upper())
        except ValueError:
            return None

    def _finding_references(
        self, finding: WizVulnerabilityFinding
    ) -> list[ExternalReference]:
        references = []
        if finding.portal_url:
            references.append(
                ExternalReference(
                    source_name="Wiz",
                    url=finding.portal_url,  # taken from the API, never rebuilt
                    external_id=finding.id,
                    description="Wiz vulnerability finding",
                )
            )
        return references
