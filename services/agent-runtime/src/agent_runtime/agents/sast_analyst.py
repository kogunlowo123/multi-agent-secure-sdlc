"""SAST analyst agent: runs and interprets SAST results."""
from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class SASTAnalystAgent:
    """Runs SAST scans via semgrep and returns structured, prioritized findings."""

    async def analyze(
        self,
        code: str,
        language: str,
    ) -> list[dict[str, Any]]:
        """Analyze code with semgrep and return prioritized SAST findings.

        Args:
            code: Source code or diff to analyze.
            language: Programming language identifier.

        Returns:
            List of SAST finding dictionaries with CWE mappings.
        """
        from agent_runtime.tools.sast_scan import SASTScanTool

        tool = SASTScanTool()
        raw_findings = await tool.scan(code=code, language=language)

        # Convert SASTFinding Pydantic models to dicts, sorted by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings_dicts = [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "title": f.title,
                "message": f.message,
                "severity": f.severity,
                "cwe_id": f.cwe_id,
                "owasp_category": f.owasp_category,
                "file_path": f.file_path,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "code_snippet": f.code_snippet,
                "fix_guidance": f.fix_guidance,
            }
            for f in raw_findings
        ]

        findings_dicts.sort(key=lambda x: severity_order.get(x["severity"], 5))

        logger.info(
            "sast_analysis_complete",
            total_findings=len(findings_dicts),
            critical=sum(1 for f in findings_dicts if f["severity"] == "CRITICAL"),
            high=sum(1 for f in findings_dicts if f["severity"] == "HIGH"),
        )
        return findings_dicts
