#!/usr/bin/env python3
"""Score OpenAudit lab results against ground truth.

Usage: evaluate.py <expected.json> <results-dir>
Writes a Markdown report to stdout.
"""
import json
import sys
from collections import Counter
from pathlib import Path


def load_report(out: Path, sid: str):
    path = out / f"{sid}.json"
    exit_code = (out / f"{sid}.exit").read_text().strip() if (out / f"{sid}.exit").exists() else "?"
    stderr = (out / f"{sid}.err").read_text().strip() if (out / f"{sid}.err").exists() else ""
    try:
        return json.loads(path.read_text()), exit_code, stderr, None
    except Exception as exc:  # noqa: BLE001 - report any parse failure
        return None, exit_code, stderr, str(exc)


def main() -> int:
    truth = json.loads(Path(sys.argv[1]).read_text())["scenarios"]
    out = Path(sys.argv[2])

    tp = fp = fn = 0
    fn_defect = fn_gap = 0
    rows = []
    invalid_json = []
    unredacted = []
    fingerprints = {}

    for sid, spec in truth.items():
        report, code, stderr, err = load_report(out, sid)
        if report is None:
            invalid_json.append(f"{sid}: {err} (exit={code}) {stderr[:200]}")
            rows.append((sid, spec, [], "INVALID", 0, 0, len(spec["expected"])))
            fn += len(spec["expected"])
            continue

        got = Counter(f["finding"]["rule_id"] for f in report["findings"])
        exp = Counter(spec["expected"])
        s_tp = sum((got & exp).values())
        s_fp = sum((got - exp).values())
        s_fn = sum((exp - got).values())
        tp, fp, fn = tp + s_tp, fp + s_fp, fn + s_fn
        if s_fn:
            cause = spec.get("cause", "")
            if cause.startswith("catalog-gap"):
                fn_gap += s_fn
            else:
                fn_defect += s_fn

        for item in report["findings"]:
            if not item["evidence"].get("is_redacted", False):
                unredacted.append(sid)
        fingerprints[sid] = sorted(f["finding"]["fingerprint"] for f in report["findings"])
        fingerprints[sid + "#asset"] = report["asset"]["id"]

        verdict = "PASS" if s_fp == 0 and s_fn == 0 else "FAIL"
        rows.append((sid, spec, sorted(got.elements()), verdict, s_tp, s_fp, s_fn))

    misconfigs = [s for s in truth.values() if s["kind"] == "misconfig"]
    expected_total = sum(len(s["expected"]) for s in truth.values())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    print("# OpenAudit Detection Lab Results\n")
    print(f"- Scenarios: {len(truth)} ({len(misconfigs)} misconfiguration, "
          f"{len(truth) - len(misconfigs)} control)")
    print(f"- Expected findings: {expected_total}")
    print(f"- True positives: {tp} | False positives: {fp} | False negatives: {fn} "
          f"({fn_defect} engine-defect, {fn_gap} catalog-gap)")
    print(f"- Precision: {precision:.0%} | Recall: {recall:.0%}")
    print(f"- Invalid JSON reports: {len(invalid_json)}")
    print(f"- Findings with unredacted evidence flag: {len(unredacted)}\n")

    print("| ID | Scenario | Kind | Expected | Reported | TP | FP | FN | Verdict |")
    print("|---|---|---|---|---|---|---|---|---|")
    for sid, spec, got, verdict, s_tp, s_fp, s_fn in rows:
        short = lambda ids: ", ".join(i.split(".", 1)[1] for i in ids) or "-"  # noqa: E731
        print(f"| {sid} | {spec['desc']} | {spec['kind']} | {short(spec['expected'])} | "
              f"{short(got)} | {s_tp} | {s_fp} | {s_fn} | {verdict} |")

    print("\n## Determinism (S00 vs S00b, identical host state)\n")
    a, b = fingerprints.get("S00#asset"), fingerprints.get("S00b#asset")
    print(f"- asset.id S00:  `{a}`\n- asset.id S00b: `{b}`")
    print(f"- Stable asset identity across runs: {'YES' if a == b else 'NO'}")

    if invalid_json:
        print("\n## Invalid reports\n")
        for line in invalid_json:
            print(f"- {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

