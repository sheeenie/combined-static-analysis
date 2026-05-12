#!/usr/bin/env python3
"""Design-science CVE validation for the libpng pipeline.

Reads docs/libpng_cve_ground_truth.json and, for each documented CVE per
pinned tag, reports which SARIF suites under results/libpng-<tag>.*.sarif
produced a finding that lands in the vulnerable file (optionally narrowed
to the vulnerable function or line range).

This is the manual TP-validation step that summarize_sarif.py cannot do on
real-world code, because it relies on Juliet's bad/good function-name
heuristic.

Usage:
  python3 scripts/cve_validation.py              # all tags in ground truth
  python3 scripts/cve_validation.py v1.6.34      # restrict to one tag
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# Reuse SHARD_ROOTS so we can register libpng dirs for resolve_artifact.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from summarize_sarif import SHARD_ROOTS, resolve_artifact  # noqa: E402

# summarize_sarif.enclosing_function is intentionally NOT reused here. Its
# FUNC_DEF_RE is tuned to Juliet's K&R "type and name on one line" style and
# mis-classifies libpng's `if (...)` blocks as functions when the brace lands
# on the next line. For CVE validation we derive function line ranges directly
# from the cloned source instead.

GROUND_TRUTH_FILE = Path("docs/libpng_cve_ground_truth.json")
RESULTS_ROOT = Path("results")
TARGETS_ROOT = Path("targets")


def register_libpng_roots() -> None:
    """Teach summarize_sarif's resolver where libpng sources live, keyed by
    the SARIF shard prefix (e.g. 'libpng-v1.6.37')."""
    if not TARGETS_ROOT.exists():
        return
    for d in TARGETS_ROOT.iterdir():
        if d.is_dir() and d.name.startswith("libpng-"):
            SHARD_ROOTS[d.name] = d


def load_ground_truth() -> dict:
    if not GROUND_TRUTH_FILE.exists():
        print(f"missing {GROUND_TRUTH_FILE}", file=sys.stderr)
        sys.exit(2)
    return json.loads(GROUND_TRUTH_FILE.read_text())


def sarifs_for_tag(tag: str) -> list[Path]:
    return sorted(RESULTS_ROOT.glob(f"libpng-{tag}.*.sarif"))


def suite_label(sarif: Path) -> str:
    stem = sarif.name[: -len(".sarif")]
    return stem.rsplit(".", 1)[1] if "." in stem else stem


def file_matches(uri: str, want: str) -> bool:
    return uri.endswith("/" + want) or uri == want or uri.endswith(want)


# Line that *could* be the start of a function definition in libpng style:
# starts at column 0, begins with an identifier followed by `(`. Used both for
# locating the target function and for finding the start of the *next* function
# so we can scope the line range.
_DEF_LINE_RE = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*\s*\(")


def function_line_range(src_root: Path, file_name: str, func_name: str) -> tuple[int, int] | None:
    """Return (start_line, end_line), 1-based, that contain `func_name` in
    `file_name` under `src_root`. The start is widened by 5 lines to absorb
    the return-type comment line that libpng puts directly above the name
    (e.g. `png_size_t /* PRIVATE */`). Returns None if the function isn't
    found in the file."""
    p = src_root / file_name
    if not p.exists():
        return None
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    start = None
    needle = func_name + "("
    needle_sp = func_name + " ("
    for i, line in enumerate(lines):
        if line.startswith(needle) or line.startswith(needle_sp):
            start = i
            break
    if start is None:
        return None
    end = len(lines) - 1
    for j in range(start + 1, len(lines)):
        if _DEF_LINE_RE.match(lines[j]):
            end = j - 1
            break
    return (max(1, start + 1 - 5), end + 1)


def check_cve(cve: dict, sarifs: list[Path], src_root: Path | None) -> dict[str, list[tuple]]:
    want_file = cve["file"]
    want_func = cve.get("function")

    # Prefer source-derived line range over the JSON-pinned one, since exact
    # line numbers shift between micro-releases. Fall back to explicit
    # line_range in the ground truth, then to "anywhere in file".
    derived: tuple[int, int] | None = None
    if want_func and src_root is not None:
        derived = function_line_range(src_root, want_file, want_func)
    if derived:
        line_lo, line_hi = derived
    else:
        line_lo, line_hi = (cve.get("line_range") or [0, 10**9])

    hits: dict[str, list[tuple]] = defaultdict(list)
    for sp in sarifs:
        suite = suite_label(sp)
        try:
            sarif = json.loads(sp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        run = sarif["runs"][0]
        for r in run.get("results", []):
            loc = r.get("locations", [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", 0) or 0
            if not file_matches(uri, want_file):
                continue
            if not (line_lo <= line <= line_hi):
                continue
            hits[suite].append((uri, line, r.get("ruleId", "")))
    return hits, (line_lo, line_hi)


def print_tag(tag: str, cves: list[dict]) -> None:
    sarifs = sarifs_for_tag(tag)
    print(f"\n== {tag}  ({len(sarifs)} SARIF(s) found under results/)")
    if not sarifs:
        print("   (no SARIFs — run `LIBPNG_ONLY=1 ./scripts/run_experiments.sh` first)")
        return
    if not cves:
        print("   No documented CVEs at this tag (clean baseline).")
        return

    src_root = TARGETS_ROOT / f"libpng-{tag}"
    src_root = src_root if src_root.exists() else None

    for cve in cves:
        print(f"\n  {cve['id']} — {cve['summary']}")
        print(f"    site: {cve['file']}:{cve.get('function', '<any>')}")
        print(f"    fixed_in: {cve.get('fixed_in', '?')}    cwe: {', '.join(cve.get('cwe', []))}")

        hits, (lo, hi) = check_cve(cve, sarifs, src_root)
        print(f"    line range used: {lo}-{hi}  (source-derived)" if hi - lo < 10**8 else
              f"    line range used: any  (function not located in source)")
        if not hits:
            print("    >>> NO suite produced a finding at this site.")
            continue
        suite_order = [
            "stock",
            "isolated-taint", "isolated-buffer", "isolated-integer", "isolated-controlflow",
            "combo-taint-buffer", "combo-taint-buffer-flow",
            "combo-taint-controlflow", "combo-integer-taint", "combo-buffer-integer",
        ]
        seen = set()
        for suite in suite_order + sorted(hits):
            if suite in seen or suite not in hits:
                continue
            seen.add(suite)
            print(f"    [{suite:<26}] {len(hits[suite])} hit(s)")
            for uri, line, rule in hits[suite][:3]:
                print(f"        {uri}:{line}  rule={rule}")
            if len(hits[suite]) > 3:
                print(f"        ... +{len(hits[suite]) - 3} more")


def main() -> int:
    register_libpng_roots()
    gt = load_ground_truth()
    tag_filter = sys.argv[1] if len(sys.argv) > 1 else None
    for tag, cves in gt.items():
        if tag.startswith("_"):
            continue
        if tag_filter and tag != tag_filter:
            continue
        print_tag(tag, cves)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
