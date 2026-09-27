"""Code reviewer agent: AI-powered security code review using LiteLLM."""
from __future__ import annotations

import json
import uuid
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

SYSTEM_PROMPT = """You are an expert security code reviewer specializing in identifying security vulnerabilities.

Analyze code changes and identify:
- OWASP Top 10 vulnerabilities (injection, broken auth, XSS, SSRF, etc.)
- CWE pattern matches (SQL injection CWE-89, command injection CWE-78, etc.)
- Hardcoded secrets and credentials (CWE-259, CWE-798)
- Insecure cryptographic usage (MD5/SHA1 for passwords, weak keys)
- SQL injection, command injection, LDAP injection
- Path traversal vulnerabilities (CWE-22)
- Insecure deserialization (CWE-502)
- Missing input validation

For each finding, respond ONLY with valid JSON array. Empty array [] if no findings.

Each finding object must have ALL these fields:
{
  "id": "<uuid>",
  "title": "<short specific title>",
  "description": "<what the vulnerability is and why it matters>",
  "severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
  "owasp_category": "<A0X:2021-Name or null>",
  "cwe_id": "<CWE-NNN or null>",
  "file_path": "<filename or null>",
  "line_number": <integer or null>,
  "recommendation": "<concrete fix>",
  "citations": []
}

Severity guidelines:
- CRITICAL: Remote code execution, authentication bypass, hardcoded credentials
- HIGH: SQL injection, command injection, deserialization, path traversal
- MEDIUM: XSS, CSRF, insecure crypto, information disclosure
- LOW: Missing security headers, verbose errors
- INFO: Code quality issues with security implications"""


class CodeReviewerAgent:
    """AI-powered code security reviewer using Azure OpenAI via LiteLLM."""

    async def review(
        self,
        code_diff: str,
        language: str,
        repository: str = "",
    ) -> list[dict[str, Any]]:
        """Review code diff for security vulnerabilities.

        Attempts LLM-based review first; falls back to heuristic scanning
        when LLM is unavailable or returns invalid output.

        Args:
            code_diff: Code diff or raw source code to review.
            language: Programming language of the code.
            repository: Repository identifier for context.

        Returns:
            List of security finding dictionaries.
        """
        try:
            return await self._llm_review(code_diff, language, repository)
        except Exception as exc:
            logger.warning("llm_review_unavailable_using_heuristic", error=str(exc))
            return self._heuristic_review(code_diff, language)

    async def _llm_review(
        self, code_diff: str, language: str, repository: str
    ) -> list[dict[str, Any]]:
        """Perform LLM-based code review via LiteLLM/Azure OpenAI."""
        import litellm
        from api.config import get_settings

        settings = get_settings()

        if not settings.azure_openai_endpoint or not settings.azure_openai_api_key:
            raise ValueError("Azure OpenAI not configured")

        response = await litellm.acompletion(
            model=f"azure/{settings.azure_openai_deployment_name}",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Review this {language} code for security vulnerabilities"
                        f"{f' in repository {repository}' if repository else ''}:\n\n"
                        f"```{language}\n{code_diff[:8000]}\n```\n\n"
                        "Respond with JSON array of findings only."
                    ),
                },
            ],
            api_base=settings.azure_openai_endpoint,
            api_key=settings.azure_openai_api_key,
            api_version=settings.azure_openai_api_version,
            temperature=0.1,
            max_tokens=4096,
        )

        content = response.choices[0].message.content.strip()

        # Strip markdown code block if present
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        findings: list[dict[str, Any]] = json.loads(content)
        if not isinstance(findings, list):
            raise ValueError(f"LLM returned non-list: {type(findings)}")

        # Ensure all findings have an id
        for f in findings:
            if "id" not in f or not f["id"]:
                f["id"] = str(uuid.uuid4())

        return findings

    def _heuristic_review(
        self, code: str, language: str
    ) -> list[dict[str, Any]]:
        """Pattern-based security review as fallback when LLM is unavailable."""
        findings: list[dict[str, Any]] = []
        lines = code.split("\n")

        patterns = [
            {
                "trigger": "shell=True",
                "title": "Command Injection via shell=True",
                "description": (
                    "Using shell=True with subprocess passes the command to the shell, "
                    "enabling shell metacharacter injection when input is user-controlled."
                ),
                "severity": "HIGH",
                "owasp_category": "A03:2021-Injection",
                "cwe_id": "CWE-78",
                "recommendation": (
                    "Avoid shell=True. Pass the command as a list: "
                    "subprocess.run(['cmd', 'arg1', arg2]). "
                    "Validate all arguments against an allowlist."
                ),
            },
            {
                "trigger": "eval(",
                "title": "Code Injection via eval()",
                "description": (
                    "eval() executes arbitrary Python code. When called with user-controlled "
                    "input, it enables complete remote code execution."
                ),
                "severity": "CRITICAL",
                "owasp_category": "A03:2021-Injection",
                "cwe_id": "CWE-94",
                "recommendation": (
                    "Remove eval(). Use ast.literal_eval() for safe literal evaluation, "
                    "or redesign to avoid dynamic code execution entirely."
                ),
            },
            {
                "trigger": "pickle.loads(",
                "title": "Insecure Deserialization (pickle)",
                "description": (
                    "pickle.loads() can execute arbitrary Python code during deserialization. "
                    "Deserializing untrusted pickle data is equivalent to RCE."
                ),
                "severity": "CRITICAL",
                "owasp_category": "A08:2021-Software and Data Integrity Failures",
                "cwe_id": "CWE-502",
                "recommendation": (
                    "Use JSON or msgpack for data serialization. "
                    "If pickle is required, sign payloads with HMAC and verify before deserializing."
                ),
            },
            {
                "trigger": "hashlib.md5(",
                "title": "Weak Cryptographic Hash (MD5)",
                "description": (
                    "MD5 is cryptographically broken (collision attacks known). "
                    "It is unsuitable for password hashing, digital signatures, or integrity verification."
                ),
                "severity": "HIGH",
                "owasp_category": "A02:2021-Cryptographic Failures",
                "cwe_id": "CWE-327",
                "recommendation": (
                    "Use hashlib.sha256() or stronger for integrity checks. "
                    "For password hashing, use bcrypt, argon2, or scrypt."
                ),
            },
            {
                "trigger": "hashlib.sha1(",
                "title": "Weak Cryptographic Hash (SHA-1)",
                "description": (
                    "SHA-1 is cryptographically deprecated (SHAttered attack). "
                    "Do not use for security-sensitive purposes."
                ),
                "severity": "HIGH",
                "owasp_category": "A02:2021-Cryptographic Failures",
                "cwe_id": "CWE-328",
                "recommendation": "Replace with SHA-256 or SHA-3: hashlib.sha256().",
            },
            {
                "trigger": "os.system(",
                "title": "Command Injection via os.system()",
                "description": (
                    "os.system() passes strings to the shell. "
                    "User-controlled input enables shell injection attacks."
                ),
                "severity": "HIGH",
                "owasp_category": "A03:2021-Injection",
                "cwe_id": "CWE-78",
                "recommendation": (
                    "Replace with subprocess.run(cmd_list, shell=False). "
                    "Pass commands as lists, not strings."
                ),
            },
        ]

        for line_num, line in enumerate(lines, 1):
            for pattern_def in patterns:
                if pattern_def["trigger"] in line:
                    finding = {
                        "id": str(uuid.uuid4()),
                        "title": pattern_def["title"],
                        "description": pattern_def["description"],
                        "severity": pattern_def["severity"],
                        "owasp_category": pattern_def["owasp_category"],
                        "cwe_id": pattern_def["cwe_id"],
                        "file_path": "reviewed_code",
                        "line_number": line_num,
                        "recommendation": pattern_def["recommendation"],
                        "citations": [],
                    }
                    findings.append(finding)
                    break  # One finding per line

        return findings
