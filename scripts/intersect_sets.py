#!/usr/bin/env python3
"""Per-tag combination report for the four analysis pairs.

Two relationship kinds, each with a primary operator:

  dependency       One analysis filters the other. The security-relevant
                   set is the intersection: a buffer-overflow candidate
                   only matters when it is also attacker-reachable.
                       taint + buffer  ->  buffer intersect taint

  complementary    Each analysis covers a different bug family and either
                   one alone is sufficient evidence of an issue. The
                   primary set is the union; the same-function
                   intersection is still reported as the higher-confidence
                   subset.
                       integer + taint, integer + buffer,
                       taint + controlflow

For each (tag, pair) we print |A|, |B|, |A union B|, |A intersect B| where
the granularity for the set operations is the enclosing function.

Usage:
  python3 scripts/intersect_sets.py                    # all tags
  python3 scripts/intersect_sets.py v1.6.34            # one tag
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

TARGETS_ROOT = Path("targets")
RESULTS_ROOT = Path("results")

_NAME_RE = re.compile(r"^([A-Za-z_][A-Za-z_0-9]*)\s*\(")
_FUNC_INDEX_CACHE: dict[Path, list[tuple[int, int, str]]] = {}

# (label, suite_a, suite_b, relationship)
PAIRS = [
    ("taint + buffer",       "isolated-buffer",      "isolated-taint", "dependency"),
    ("integer + taint",      "isolated-integer",     "isolated-taint", "complementary"),
    ("integer + buffer",     "isolated-integer",     "isolated-buffer", "complementary"),
    ("taint + controlflow",  "isolated-controlflow", "isolated-taint", "complementary"),
]


def build_function_index(src_path: Path) -> list[tuple[int, int, str]]:
    if src_path in _FUNC_INDEX_CACHE:
        return _FUNC_INDEX_CACHE[src_path]
    if not src_path.exists():
        _FUNC_INDEX_CACHE[src_path] = []
        return []
    try:
        lines = src_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        _FUNC_INDEX_CACHE[src_path] = []
        return []

    starts: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = _NAME_RE.match(line)
        if not m:
            continue
        for j in range(i, min(i + 5, len(lines))):
            t = lines[j].strip()
            if not t:
                continue
            if t.endswith("{") or t == "{":
                starts.append((i + 1, m.group(1)))
                break
            if t.endswith(";"):
                break

    out: list[tuple[int, int, str]] = []
    for k, (s, name) in enumerate(starts):
        end = starts[k + 1][0] - 1 if k + 1 < len(starts) else 10**9
        out.append((s, end, name))
    _FUNC_INDEX_CACHE[src_path] = out
    return out


def lookup_function(src_root: Path, uri: str, line: int) -> str | None:
    if not uri or not line:
        return None
    src = src_root / uri
    idx = build_function_index(src)
    for start, end, name in idx:
        if start <= line <= end:
            return name
    return None


def load_sarif_results(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))["runs"][0].get("results", [])


def map_to_functions(results: list[dict], src_root: Path):
    """Return (by_func, unresolved). by_func[name] = [(rule, uri, line), ...]."""
    by_func: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
    unresolved = 0
    for r in results:
        loc = r.get("locations", [{}])[0].get("physicalLocation", {})
        uri = loc.get("artifactLocation", {}).get("uri", "")
        line = loc.get("region", {}).get("startLine", 0) or 0
        func = lookup_function(src_root, uri, line)
        if not func:
            unresolved += 1
            continue
        by_func[func].append((r.get("ruleId", ""), uri, line))
    return by_func, unresolved


def report_pair(label: str, suite_a: str, suite_b: str, relationship: str, tag: str) -> None:
    src_root = TARGETS_ROOT / f"libpng-{tag}"
    a = map_to_functions(load_sarif_results(RESULTS_ROOT / f"libpng-{tag}.{suite_a}.sarif"), src_root)[0]
    b = map_to_functions(load_sarif_results(RESULTS_ROOT / f"libpng-{tag}.{suite_b}.sarif"), src_root)[0]

    a_funcs = set(a)
    b_funcs = set(b)
    union = a_funcs | b_funcs
    inter = a_funcs & b_funcs

    a_total = sum(len(v) for v in a.values())
    b_total = sum(len(v) for v in b.values())

    primary_op = "intersection" if relationship == "dependency" else "union"
    primary_count = len(inter) if primary_op == "intersection" else len(union)

    print(f"\n  [{label}]  relationship: {relationship}   primary operator: {primary_op}")
    print(f"      |A|={a_total} in {len(a_funcs)} fn(s)   |B|={b_total} in {len(b_funcs)} fn(s)")
    print(f"      |A u B|_fn = {len(union)} fn(s)   |A n B|_fn = {len(inter)} fn(s)   "
          f"-> primary ({primary_op}) = {primary_count} fn(s)")

    # Always show the intersection contents. It is the higher-confidence
    # subset whether or not it is the primary operator for this pair.
    if inter:
        print(f"      A n B function list (both analyses fire):")
        for fn in sorted(inter)[:12]:
            print(f"        {fn}()   A:{len(a[fn])}  B:{len(b[fn])}")
        if len(inter) > 12:
            print(f"        ... +{len(inter) - 12} more")
    if relationship == "complementary":
        only_a = a_funcs - b_funcs
        only_b = b_funcs - a_funcs
        print(f"      complementary breakdown: only-A={len(only_a)} fn(s), "
              f"only-B={len(only_b)} fn(s), both={len(inter)} fn(s)")


def run_for_tag(tag: str) -> None:
    print(f"\n=== {tag} ===")
    for label, sa, sb, rel in PAIRS:
        report_pair(label, sa, sb, rel, tag)


def main() -> int:
    tag_filter = sys.argv[1] if len(sys.argv) > 1 else None
    if tag_filter:
        run_for_tag(tag_filter)
    else:
        tag_re = re.compile(r"^libpng-(.+)\.isolated-buffer\.sarif$")
        tags = sorted({
            m.group(1)
            for p in RESULTS_ROOT.glob("libpng-*.isolated-buffer.sarif")
            for m in [tag_re.match(p.name)] if m
        })
        for tag in tags:
            run_for_tag(tag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
