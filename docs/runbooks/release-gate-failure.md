# Runbook: Release Gate Failure

## Overview

This runbook describes how to diagnose and resolve a release gate failure
returned by the `POST /api/v1/release/gate` endpoint.

## Symptoms

- Release gate returns `decision: "NO-GO"`
- `blockers` list contains one or more items

## Diagnosis Steps

### 1. Check the Evidence

```bash
curl -s http://localhost:8000/api/v1/release/{release_id}/status | jq .
```

Review:
- `blockers` — specific blocking reasons
- `evidence.code_review.critical_high_count` — code review findings
- `evidence.sast.critical_high_count` — SAST findings
- `evidence.test_coverage` — coverage percentage
- `evidence.approvals` — approval status

### 2. Security Findings

If blocked by security findings, retrieve the full code review result and remediate:
- Address each `CRITICAL` finding immediately
- Address each `HIGH` finding before release
- For SAST findings, consult the `fix_guidance` field

### 3. Test Coverage

If blocked by test coverage below 70%:
```bash
make coverage  # View HTML report in htmlcov/
```

Identify untested code paths and add tests.

### 4. Approvals

If blocked by insufficient approvals:
- Request additional review from team members
- Ensure approvers have merged their reviews in the source VCS

## Re-triggering the Gate

After addressing all blockers:
```bash
curl -X POST http://localhost:8000/api/v1/release/gate \
  -H "Content-Type: application/json" \
  -d '{"release_id": "...", ...}'
```

## Escalation

If the gate consistently fails due to agent errors (`pipeline_errors` in evidence),
escalate to the platform team with the full response body.
