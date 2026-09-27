# Runbook: Security Finding Triage

## Overview

This runbook guides developers through triaging security findings
returned by the `POST /api/v1/code/review` and `POST /api/v1/sast/scan` endpoints.

## Finding Severity Guidelines

| Severity | Action Required | Timeline |
|----------|----------------|----------|
| CRITICAL | Block release, fix immediately | Same day |
| HIGH | Block release, fix before merge | Within 1 sprint |
| MEDIUM | Address in current sprint | Within 2 sprints |
| LOW | Backlog item | Quarterly review |
| INFO | Informational | As time permits |

## Common Findings and Remediations

### CWE-89: SQL Injection

**Detection**: f-string or % formatting in SQL queries

**Fix**:
```python
# BEFORE (vulnerable)
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# AFTER (safe)
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### CWE-78: Command Injection

**Detection**: `shell=True` in subprocess calls

**Fix**:
```python
# BEFORE (vulnerable)
subprocess.run(user_input, shell=True)

# AFTER (safe)
subprocess.run(["ls", "-la", safe_path], shell=False)
```

### CWE-502: Insecure Deserialization

**Detection**: `pickle.loads()` on untrusted data

**Fix**:
```python
# BEFORE (vulnerable)
obj = pickle.loads(user_data)

# AFTER (safe)
import json
obj = json.loads(user_data)  # For JSON-serializable data
```

### CWE-327/CWE-328: Weak Cryptographic Hash

**Detection**: `hashlib.md5()` or `hashlib.sha1()`

**Fix**:
```python
# BEFORE (vulnerable)
hash = hashlib.md5(password.encode()).hexdigest()

# AFTER (safe — use bcrypt for passwords)
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
# OR for non-password integrity checks:
hash = hashlib.sha256(data.encode()).hexdigest()
```

## Requesting a Finding Review

If you believe a finding is a false positive:
1. Open a GitHub issue using the "Security Finding" template
2. Document why it is not exploitable in context
3. Get sign-off from a security team member
4. Add a `# nosec: <reason>` comment if suppression is warranted
