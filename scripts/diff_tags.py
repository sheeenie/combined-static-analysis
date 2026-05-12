#!/usr/bin/env python3
"""Diff SARIF findings between a vuln tag and a fix tag of the same project.

Findings present at the vuln tag but absent at the fix tag are TP
candidates — they correspond to code that the fix commit demonstrably
altered. This is the closest mechanical equivalent to Juliet's auto
TP/FP labelling on real-world targets: you get a labelled-by-construction
subset without per-finding code reading.

Per-finding-line diffing is unreliable across micro-releases (line
numbers shift). This tool diffs at the granularity of (ruleId, file).
When the vuln tag has N findings of rule R in file F and the fix tag has
M < N, (N - M) is the count of vuln-only findings to manually inspect.

Usage:
  python3 scripts/diff_tags.py v1.6.34 v1.6.36                   # all suites
  python3 scripts/diff_tags.py v1.6.34 v1.6.36 combo-taint-buffer-flow
"""
import json
import sys
from collections import Counter
from pathlib import Path

RESULTS_ROOT = Path("results")


def load_sarif(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def file_signature(uri: str) -> str:
    """Path-stable basename, used as the per-finding cross-tag key."""
    return Path(uri).name if uri else ""


def collect(tag: str, suite: str) -> Counter:
    """Count (ruleId, file-basename) occurrences for one (tag, suite) SARIF."""
    sp = RESULTS_ROOT / f"libpng-{tag}.{suite}.sarif"
    if not sp.exists():
        return Counter()
    sarif = load_sarif(sp)
    c: Counter = Counter()
    for r in sarif["runs"][0].get("results", []):
        uri = (
            r.get("locations", [{}])[0]
            .get("physicalLocation", {})
            .get("artifactLocation", {})
            .get("uri", "")
        )
        c[(r.get("ruleId", ""), file_signature(uri))] += 1
    return c


def suites_for_tag(tag: str) -> list[str]:
    out: set[str] = set()
    for p in RESULTS_ROOT.glob(f"libpng-{tag}.*.sarif"):
        stem = p.name[: -len(".sarif")]
        suite = stem.rsplit(".", 1)[1] if "." in stem else stem
        out.add(suite)
    return sorted(out)


def diff_pair(vuln: str, fix: str, suite_filter: str | None) -> None:
    suites = suites_for_tag(vuln) if suite_filter is None else [suite_filter]
    print(f"\n=== diff {vuln} (vuln) → {fix} (fix) ===")
    print("  Reading: same (ruleId, file-basename) pairs across both SARIFs.")
    print("  A positive 'vuln-only' delta means: that (rule, file) fires more times at")
    print("  the vuln tag than at the fix tag — the difference is the TP candidate set.")

    for suite in suites:
        v = collect(vuln, suite)
        f = collect(fix, suite)
        vt = sum(v.values())
        ft = sum(f.values())
        vuln_only_pairs = [(k, v[k] - f[k]) for k in v if v[k] > f[k]]
        vuln_only_total = sum(d for _, d in vuln_only_pairs)
        # (rule, file) combinations present at vuln but missing entirely at fix.
        newly_quiet = [k for k in v if k not in f]

        print(
            f"\n  [{suite:<26}] vuln={vt:>4}  fix={ft:>4}  "
            f"vuln-only-deltas-sum={vuln_only_total}  "
            f"keys-gone-at-fix={len(newly_quiet)}"
        )
        if not vuln_only_pairs:
            continue
        sorted_pairs = sorted(vuln_only_pairs, key=lambda x: -x[1])
        for (rule, fname), delta in sorted_pairs[:10]:
            tag_mark = "!!" if (rule, fname) in newly_quiet else "  "
            print(f"     {tag_mark} +{delta:>3}  {rule}  in  {fname}")
        if len(sorted_pairs) > 10:
            print(f"        ... +{len(sorted_pairs) - 10} more (rule, file) pairs with positive vuln delta")

    print("\n  Legend:  '!!' = (rule, file) pair appears at vuln but is fully gone at fix.")


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: diff_tags.py <vuln_tag> <fix_tag> [suite]", file=sys.stderr)
        return 2
    vuln = sys.argv[1]
    fix = sys.argv[2]
    suite_filter = sys.argv[3] if len(sys.argv) > 3 else None
    diff_pair(vuln, fix, suite_filter)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
