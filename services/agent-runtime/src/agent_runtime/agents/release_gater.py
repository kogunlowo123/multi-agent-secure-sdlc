"""Release gater agent: evaluates release readiness based on security evidence."""
from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Severities that block releases
BLOCKING_SEVERITIES = frozenset({"CRITICAL", "HIGH"})

# OWASP categories that always block a release
BLOCKING_OWASP_CATEGORIES = frozenset(
    {
        "A03:2021-Injection",
        "A01:2021-Broken Access Control",
        "A02:2021-Cryptographic Failures",
        "A08:2021-Software and Data Integrity Failures",
    }
)

# Minimum test coverage to pass (strict threshold)
MIN_COVERAGE_STRICT = 70.0
# Warning threshold
MIN_COVERAGE_RECOMMENDED = 80.0


class ReleaseGaterAgent:
    """Evaluates release readiness from security evidence and produces go/no-go decision."""

    async def evaluate(
        self,
        findings: list[dict[str, Any]],
        sast_findings: list[dict[str, Any]],
        metadata: dict[str, Any],
        errors: list[str],
    ) -> dict[str, Any]:
        """Evaluate release readiness.

        Args:
            findings: Code review security findings from the code-reviewer agent.
            sast_findings: SAST scan findings from the sast-analyst agent.
            metadata: Release metadata (test_coverage, approvals, etc.).
            errors: Accumulated errors from previous pipeline stages.

        Returns:
            Decision dictionary with decision (GO|NO-GO), status, blockers,
            warnings, and evidence trail.
        """
        blockers: list[str] = []
        warnings: list[str] = []
        evidence: dict[str, Any] = {}

        # --- Code review findings ---
        critical_high_findings = [
            f for f in findings if f.get("severity") in BLOCKING_SEVERITIES
        ]
        blocking_owasp = [
            f for f in findings if f.get("owasp_category") in BLOCKING_OWASP_CATEGORIES
        ]

        evidence["code_review"] = {
            "total_findings": len(findings),
            "critical_high_count": len(critical_high_findings),
            "blocking_owasp_count": len(blocking_owasp),
            "findings_by_severity": self._count_by_severity(findings),
        }

        for f in critical_high_findings:
            cwe = f.get("cwe_id", "unknown")
            loc = f"line {f.get('line_number', '?')}" if f.get("line_number") else ""
            blockers.append(
                f"[{f.get('severity')}] {f.get('title', 'Security finding')} "
                f"({cwe}) {loc}".strip()
            )

        # --- SAST findings ---
        critical_high_sast = [
            f for f in sast_findings if f.get("severity") in BLOCKING_SEVERITIES
        ]

        evidence["sast"] = {
            "total_findings": len(sast_findings),
            "critical_high_count": len(critical_high_sast),
            "findings_by_severity": self._count_by_severity(sast_findings),
        }

        for f in critical_high_sast:
            rule = f.get("rule_id", "unknown-rule")
            loc = f"{f.get('file_path', '?')}:{f.get('line_start', '?')}"
            blockers.append(
                f"[SAST/{f.get('severity')}] {f.get('title', rule)} at {loc}"
            )

        # --- Test coverage ---
        test_coverage = metadata.get("test_coverage")
        if test_coverage is not None:
            evidence["test_coverage"] = round(float(test_coverage), 2)
            if float(test_coverage) < MIN_COVERAGE_STRICT:
                blockers.append(
                    f"Test coverage {test_coverage:.1f}% is below the required {MIN_COVERAGE_STRICT:.0f}% threshold"
                )
            elif float(test_coverage) < MIN_COVERAGE_RECOMMENDED:
                warnings.append(
                    f"Test coverage {test_coverage:.1f}% is below the recommended {MIN_COVERAGE_RECOMMENDED:.0f}% threshold"
                )

        # --- SAST gate status ---
        sast_passed = metadata.get("sast_passed")
        evidence["sast_gate_passed"] = sast_passed
        if sast_passed is False:
            blockers.append("SAST scan did not pass the quality gate")
        elif sast_passed is None:
            warnings.append("SAST gate status unknown — scan may not have run")

        # --- Approvals ---
        required_approvals = int(metadata.get("required_approvals", 2))
        approvals_received = int(metadata.get("approvals_received", 0))
        evidence["approvals"] = {
            "required": required_approvals,
            "received": approvals_received,
        }
        if approvals_received < required_approvals:
            blockers.append(
                f"Insufficient approvals: {approvals_received}/{required_approvals} required"
            )

        # --- Pipeline errors ---
        if errors:
            warnings.extend([f"Pipeline agent error: {e}" for e in errors])
            evidence["pipeline_errors"] = errors

        decision = "GO" if not blockers else "NO-GO"
        status = "APPROVED" if not blockers else "BLOCKED"

        logger.info(
            "release_decision_finalized",
            decision=decision,
            status=status,
            blocker_count=len(blockers),
            warning_count=len(warnings),
        )

        return {
            "decision": decision,
            "status": status,
            "blockers": blockers,
            "warnings": warnings,
            "evidence": evidence,
        }

    @staticmethod
    def _count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
        """Count findings grouped by severity level."""
        counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        return counts
