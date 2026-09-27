# ADR 0002: Release Gate Evidence Requirements

**Date**: 2024-01-01
**Status**: Accepted
**Deciders**: Platform Team

## Context

The release-gater agent must make consistent, auditable release decisions
backed by security evidence. We need to define what evidence is required
and what constitutes a blocking condition.

## Decision

### Blocking Conditions (NO-GO)

The following conditions will block a release:

1. **CRITICAL or HIGH severity security findings** from code review
2. **CRITICAL or HIGH severity SAST findings** from semgrep
3. **Test coverage < 70%** (configurable per team)
4. **SAST gate explicitly failed** (sast_passed=False)
5. **Insufficient approvals** (approvals_received < required_approvals)

### Warning Conditions (GO with warnings)

1. **Test coverage 70-79%** (below 80% recommended threshold)
2. **SAST gate status unknown** (scan may not have run)
3. **Agent pipeline errors** (degraded mode)

### Evidence Trail

Every release decision includes an immutable evidence dict containing:
- `code_review.total_findings` and `code_review.critical_high_count`
- `sast.total_findings` and `sast.critical_high_count`
- `test_coverage` percentage
- `sast_gate_passed` boolean
- `approvals.required` and `approvals.received`
- `pipeline_errors` list (if any)

## Rationale

A zero-tolerance policy on CRITICAL/HIGH findings reduces the mean time
to breach by preventing known-exploitable patterns from reaching production.
Evidence is stored per release_id enabling post-incident audit.

## Consequences

- Teams must achieve 70%+ test coverage before releasing
- All CRITICAL/HIGH SAST findings must be remediated before release
- Release gater decisions are auditable with full evidence trail
