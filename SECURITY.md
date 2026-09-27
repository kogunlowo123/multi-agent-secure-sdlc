# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a Vulnerability

We take security vulnerabilities seriously. Please **do not** open public GitHub issues for security vulnerabilities.

### How to Report

1. Email: security@example.com
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested remediation (if available)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Status Update**: Every 7 days during investigation
- **Resolution**: Target 90 days for critical/high issues

### Disclosure Policy

We follow coordinated disclosure:
1. Report received and acknowledged
2. Vulnerability validated and severity assessed
3. Fix developed and tested
4. Fix deployed to production
5. Public disclosure after users have had time to update (minimum 30 days)

## Out of Scope

- Denial of service attacks
- Social engineering
- Physical attacks
- Vulnerabilities in third-party dependencies (report to the dependency maintainer)

## Security Best Practices for Contributors

- Never commit secrets, API keys, or credentials
- Use parameterized queries for database access
- Validate and sanitize all user inputs
- Follow OWASP Top 10 guidelines
- Ensure all dependencies are up to date
- Run `make semgrep` before submitting PRs
