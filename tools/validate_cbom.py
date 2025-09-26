#!/usr/bin/env python3
import argparse
import json
import sys
from typing import Any, Dict, List, Tuple


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
VULN_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def count_findings(findings: List[Dict[str, Any]]) -> Tuple[Dict[str, int], Dict[str, int], int, int]:
    risk_counts: Dict[str, int] = {}
    algo_counts: Dict[str, int] = {}
    vuln_assets = 0
    quantum_safe = 0

    for finding in findings:
        risk = str(finding.get("risk", "UNKNOWN")).upper()
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

        algo = str(finding.get("algorithm", "unknown"))
        algo_counts[algo] = algo_counts.get(algo, 0) + 1

        quantum_resistant = bool(finding.get("quantum_resistant", False))
        if quantum_resistant:
            quantum_safe += 1

        # Vulnerable assets = severities CRITICAL/HIGH/MEDIUM and not quantum-resistant
        if risk in VULN_SEVERITIES and not quantum_resistant:
            vuln_assets += 1

    return risk_counts, algo_counts, vuln_assets, quantum_safe


def compare_summary(doc: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    findings = doc.get("findings") or []
    if not isinstance(findings, list):
        errors.append("findings is not an array")
        return False, errors

    risk_counts, algo_counts, vuln_assets, quantum_safe = count_findings(findings)

    summary = doc.get("summary") or {}
    ok = True

    # Compare quantum_safe_assets
    if "quantum_safe_assets" in summary:
        if int(summary.get("quantum_safe_assets", -1)) != int(quantum_safe):
            ok = False
            errors.append(
                f"summary.quantum_safe_assets={summary.get('quantum_safe_assets')} != computed {quantum_safe}"
            )

    # Compare vulnerable_assets
    if "vulnerable_assets" in summary:
        if int(summary.get("vulnerable_assets", -1)) != int(vuln_assets):
            ok = False
            errors.append(
                f"summary.vulnerable_assets={summary.get('vulnerable_assets')} != computed {vuln_assets}"
            )

    # Compare risk_breakdown
    s_risk = (summary.get("risk_breakdown") or {}) if isinstance(summary, dict) else {}
    for sev, count in risk_counts.items():
        if s_risk.get(sev) is not None and int(s_risk.get(sev)) != int(count):
            ok = False
            errors.append(f"summary.risk_breakdown[{sev}]={s_risk.get(sev)} != computed {count}")

    # Compare algorithm_breakdown
    s_algo = (summary.get("algorithm_breakdown") or {}) if isinstance(summary, dict) else {}
    for algo, count in algo_counts.items():
        if s_algo.get(algo) is not None and int(s_algo.get(algo)) != int(count):
            ok = False
            errors.append(f"summary.algorithm_breakdown[{algo}]={s_algo.get(algo)} != computed {count}")

    return ok, errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate CBOM JSON summary consistency")
    parser.add_argument("files", nargs="+", help="Path(s) to CBOM JSON file(s)")
    args = parser.parse_args()

    all_ok = True
    for path in args.files:
        try:
            doc = load_json(path)
        except Exception as e:
            print(f"[FAIL] {path}: invalid JSON: {e}")
            all_ok = False
            continue

        ok, errors = compare_summary(doc)
        if ok:
            print(f"[OK] {path}: summary matches findings")
        else:
            all_ok = False
            print(f"[FAIL] {path}:")
            for err in errors:
                print(f"  - {err}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())


