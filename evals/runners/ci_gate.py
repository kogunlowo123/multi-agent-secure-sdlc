"""CI evaluation gate: runs golden dataset and asserts quality thresholds."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

GOLDEN_DATASET = Path(__file__).parent.parent / "datasets" / "golden" / "code-review-qa-pairs.jsonl"
MIN_RECALL_THRESHOLD = 0.80  # 80% of expected CWEs must be detected


async def run_evaluation() -> dict:
    """Run the CI quality gate evaluation against the golden dataset."""
    from agent_runtime.tools.sast_scan import SASTScanTool

    tool = SASTScanTool(timeout=60)
    results = {"passed": 0, "failed": 0, "errors": 0, "details": []}

    with open(GOLDEN_DATASET) as f:
        test_cases = [json.loads(line) for line in f if line.strip()]

    for tc in test_cases:
        tc_id = tc["id"]
        try:
            findings = await tool.scan(
                code=tc["input"]["code"],
                language=tc["input"]["language"],
            )

            expected = tc["expected"]
            passed = True
            reasons = []

            # Check min_findings
            if "min_findings" in expected and len(findings) < expected["min_findings"]:
                passed = False
                reasons.append(
                    f"Too few findings: {len(findings)} < {expected['min_findings']}"
                )

            # Check required CWEs
            if "required_cwe" in expected:
                detected_cwes = {f.cwe_id for f in findings if f.cwe_id}
                for cwe in expected["required_cwe"]:
                    if cwe not in detected_cwes:
                        passed = False
                        reasons.append(f"Missing required CWE: {cwe}")

            # Check required severity
            if "required_severity" in expected:
                detected_sevs = {f.severity for f in findings}
                if not any(s in detected_sevs for s in expected["required_severity"]):
                    passed = False
                    reasons.append(
                        f"Missing required severity: {expected['required_severity']}"
                    )

            # Check max critical/high
            if "max_critical_high" in expected:
                critical_high = sum(
                    1 for f in findings if f.severity in ("CRITICAL", "HIGH")
                )
                if critical_high > expected["max_critical_high"]:
                    passed = False
                    reasons.append(
                        f"Too many critical/high: {critical_high} > {expected['max_critical_high']}"
                    )

            result_entry = {"id": tc_id, "passed": passed, "reasons": reasons}
            results["details"].append(result_entry)
            if passed:
                results["passed"] += 1
            else:
                results["failed"] += 1
                logger.warning("eval_case_failed", id=tc_id, reasons=reasons)

        except Exception as exc:
            results["errors"] += 1
            results["details"].append({"id": tc_id, "error": str(exc)})
            logger.error("eval_case_error", id=tc_id, error=str(exc))

    total = results["passed"] + results["failed"] + results["errors"]
    recall = results["passed"] / total if total > 0 else 0.0
    results["recall"] = recall
    results["threshold"] = MIN_RECALL_THRESHOLD
    results["gate_passed"] = recall >= MIN_RECALL_THRESHOLD

    return results


if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "services" / "api" / "src"))
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "services" / "agent-runtime" / "src"))

    results = asyncio.run(run_evaluation())
    print(json.dumps(results, indent=2))
    sys.exit(0 if results["gate_passed"] else 1)
