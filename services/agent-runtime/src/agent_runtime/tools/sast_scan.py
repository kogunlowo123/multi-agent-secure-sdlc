"""SAST scanning tool using semgrep subprocess execution."""
from __future__ import annotations

import json
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

LANGUAGE_EXTENSIONS: dict[str, str] = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "go": ".go",
    "ruby": ".rb",
    "php": ".php",
    "csharp": ".cs",
    "cpp": ".cpp",
    "c": ".c",
    "rust": ".rs",
    "kotlin": ".kt",
    "swift": ".swift",
}

# Map semgrep severity to normalized values
SEVERITY_MAP: dict[str, str] = {
    "ERROR": "CRITICAL",
    "WARNING": "HIGH",
    "INFO": "MEDIUM",
    "LOW": "LOW",
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
}

# CWE to OWASP mapping
CWE_OWASP_MAP: dict[str, str] = {
    "CWE-89": "A03:2021-Injection",
    "CWE-78": "A03:2021-Injection",
    "CWE-79": "A03:2021-Injection",
    "CWE-94": "A03:2021-Injection",
    "CWE-502": "A08:2021-Software and Data Integrity Failures",
    "CWE-327": "A02:2021-Cryptographic Failures",
    "CWE-328": "A02:2021-Cryptographic Failures",
    "CWE-259": "A07:2021-Identification and Authentication Failures",
    "CWE-798": "A07:2021-Identification and Authentication Failures",
    "CWE-22": "A01:2021-Broken Access Control",
    "CWE-918": "A10:2021-Server-Side Request Forgery",
    "CWE-611": "A05:2021-Security Misconfiguration",
    "CWE-601": "A01:2021-Broken Access Control",
}

FIX_GUIDANCE_MAP: dict[str, str] = {
    "CWE-89": "Use parameterized queries or an ORM. Never concatenate user input into SQL strings.",
    "CWE-78": "Pass commands as lists to subprocess.run(). Avoid shell=True with user input.",
    "CWE-94": "Remove eval()/exec(). Use ast.literal_eval() for safe literal evaluation.",
    "CWE-502": "Replace pickle with JSON or msgpack. Never deserialize untrusted data.",
    "CWE-327": "Replace MD5/SHA1 with SHA-256 (hashlib.sha256()). Use bcrypt/argon2 for passwords.",
    "CWE-328": "Replace SHA-1 with SHA-256 or stronger.",
    "CWE-259": "Store credentials in environment variables or a secrets manager (Azure Key Vault).",
    "CWE-798": "Move hardcoded secrets to environment variables or Azure Key Vault.",
    "CWE-22": "Validate file paths against an allowed root directory. Use Path.resolve().",
    "CWE-918": "Validate URLs against an allowlist before making outbound HTTP requests.",
}


class SASTScanTool:
    """SAST scanning tool that uses semgrep to detect security vulnerabilities."""

    def __init__(self, timeout: int = 120) -> None:
        """Initialize with configurable scan timeout."""
        self.timeout = timeout

    async def scan(self, code: str, language: str) -> list[Any]:
        """Run SAST scan on provided code.

        Args:
            code: Source code or diff to scan.
            language: Programming language identifier.

        Returns:
            List of SASTFinding objects.
        """
        from api.schemas.vulnerability import SASTFinding

        ext = LANGUAGE_EXTENSIONS.get(language.lower(), ".py")

        with tempfile.TemporaryDirectory() as tmpdir:
            code_file = Path(tmpdir) / f"code{ext}"
            code_file.write_text(code, encoding="utf-8")

            raw_results = self._run_semgrep(str(code_file), language, tmpdir)
            return self._parse_results(raw_results, str(code_file))

    def _run_semgrep(
        self, code_path: str, language: str, work_dir: str
    ) -> dict[str, Any]:
        """Execute semgrep and return parsed JSON output."""
        cmd = [
            "semgrep",
            "--config=auto",
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--timeout", str(self.timeout),
            code_path,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 10,
                cwd=work_dir,
            )

            stdout = result.stdout.strip()
            if stdout:
                try:
                    return json.loads(stdout)
                except json.JSONDecodeError:
                    logger.warning("semgrep_invalid_json", stdout_preview=stdout[:200])

            if result.returncode not in (0, 1):
                logger.warning(
                    "semgrep_nonzero_exit",
                    returncode=result.returncode,
                    stderr=result.stderr[:500] if result.stderr else "",
                )

            return {"results": [], "errors": []}

        except subprocess.TimeoutExpired:
            logger.warning("semgrep_timeout", timeout=self.timeout)
            return {"results": [], "errors": [{"message": f"Scan timed out after {self.timeout}s"}]}

        except FileNotFoundError:
            logger.warning("semgrep_not_found_using_heuristic")
            return self._heuristic_scan(code_path)

        except Exception as exc:
            logger.error("semgrep_unexpected_error", error=str(exc))
            return {"results": [], "errors": [{"message": str(exc)}]}

    def _heuristic_scan(self, code_path: str) -> dict[str, Any]:
        """Fallback heuristic pattern scan when semgrep is not installed."""
        try:
            with open(code_path, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError:
            return {"results": [], "errors": []}

        results = []
        patterns = [
            {
                "pattern": "shell=True",
                "rule_id": "python.subprocess.security.audit.subprocess-shell-true",
                "message": "subprocess called with shell=True allows shell injection",
                "severity": "ERROR",
                "cwe": "CWE-78",
            },
            {
                "pattern": "eval(",
                "rule_id": "python.lang.security.audit.eval-detected",
                "message": "Use of eval() enables arbitrary code injection",
                "severity": "ERROR",
                "cwe": "CWE-94",
            },
            {
                "pattern": "pickle.loads(",
                "rule_id": "python.lang.security.audit.pickle-deserialization",
                "message": "Insecure deserialization with pickle allows arbitrary code execution",
                "severity": "ERROR",
                "cwe": "CWE-502",
            },
            {
                "pattern": "hashlib.md5(",
                "rule_id": "python.lang.security.audit.md5-used",
                "message": "MD5 is cryptographically broken; use SHA-256 or stronger",
                "severity": "WARNING",
                "cwe": "CWE-327",
            },
            {
                "pattern": "hashlib.sha1(",
                "rule_id": "python.lang.security.audit.sha1-used",
                "message": "SHA-1 is cryptographically deprecated; use SHA-256 or stronger",
                "severity": "WARNING",
                "cwe": "CWE-328",
            },
            {
                "pattern": "os.system(",
                "rule_id": "python.lang.security.audit.os-system-injection",
                "message": "os.system() passes input to shell, enabling command injection",
                "severity": "ERROR",
                "cwe": "CWE-78",
            },
            {
                "pattern": "exec(",
                "rule_id": "python.lang.security.audit.exec-detected",
                "message": "exec() enables arbitrary code execution from user input",
                "severity": "ERROR",
                "cwe": "CWE-94",
            },
        ]

        for line_num, line in enumerate(lines, 1):
            # Strip comment portion (text after '#') to avoid false positives
            # where patterns appear only inside comments.
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            line_code = line.split("#")[0]
            for p in patterns:
                if p["pattern"] in line_code:
                    results.append(
                        {
                            "check_id": p["rule_id"],
                            "path": code_path,
                            "start": {"line": line_num},
                            "end": {"line": line_num},
                            "extra": {
                                "message": p["message"],
                                "severity": p["severity"],
                                "metadata": {"cwe": [p["cwe"]]},
                                "lines": line.rstrip(),
                            },
                        }
                    )

        return {"results": results, "errors": []}

    def _parse_results(
        self, semgrep_output: dict[str, Any], code_path: str
    ) -> list[Any]:
        """Parse semgrep JSON output into SASTFinding Pydantic models."""
        from api.schemas.vulnerability import SASTFinding

        findings: list[SASTFinding] = []
        raw_results = semgrep_output.get("results", [])

        for result in raw_results:
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            raw_severity = extra.get("severity", "INFO").upper()
            severity = SEVERITY_MAP.get(raw_severity, raw_severity)

            # Extract CWE
            cwe_list = metadata.get("cwe", [])
            if isinstance(cwe_list, str):
                cwe_list = [cwe_list]
            cwe_id = cwe_list[0] if cwe_list else None
            if cwe_id and not cwe_id.startswith("CWE-"):
                cwe_id = f"CWE-{cwe_id}"

            # Map CWE to OWASP
            owasp = metadata.get("owasp") or (CWE_OWASP_MAP.get(cwe_id) if cwe_id else None)
            if isinstance(owasp, list):
                owasp = owasp[0] if owasp else None

            rule_id = result.get("check_id", "unknown-rule")
            message = extra.get("message", "Security vulnerability detected")
            code_snippet = extra.get("lines", "")

            finding = SASTFinding(
                id=str(uuid.uuid4()),
                rule_id=rule_id,
                title=self._rule_id_to_title(rule_id),
                message=message,
                severity=severity,
                cwe_id=cwe_id,
                owasp_category=owasp,
                file_path=result.get("path", code_path),
                line_start=result.get("start", {}).get("line", 0),
                line_end=result.get("end", {}).get("line", 0),
                code_snippet=code_snippet[:500] if code_snippet else None,
                fix_guidance=FIX_GUIDANCE_MAP.get(cwe_id) if cwe_id else None,
            )
            findings.append(finding)

        logger.info(
            "sast_results_parsed",
            total=len(findings),
            raw_count=len(raw_results),
        )
        return findings

    @staticmethod
    def _rule_id_to_title(rule_id: str) -> str:
        """Convert a semgrep rule ID dotted path to a human-readable title."""
        parts = rule_id.split(".")
        if not parts:
            return rule_id
        last_part = parts[-1].replace("-", " ").replace("_", " ")
        return last_part.title()
