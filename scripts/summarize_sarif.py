#!/usr/bin/env python3
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Function-definition heuristic for Juliet-style C/C++. Matches a line that
# looks like "<rettype> <name>(...)" with no trailing semicolon. Works for the
# Juliet style where the opening brace is on the next line. The captured
# group is the function name.
FUNC_DEF_RE = re.compile(
    r"""^[ \t]*
        (?:static\s+|inline\s+|extern\s+|virtual\s+)*
        [A-Za-z_][\w\s\*\&:<>,]*?      # return type (greedy-ish)
        \s+
        ([A-Za-z_]\w*)                 # function name
        \s*\([^;{}]*\)\s*$             # parameter list, no terminator
    """,
    re.VERBOSE,
)

# Map from SARIF-filename prefix to the source root used during database
# creation. Lets the summarizer resolve relative artifact URIs without
# scanning the whole my_cases/ tree (around 40k files). Add new shards
# here as needed.
SHARD_ROOTS: dict[str, Path] = {
    "buffer-integer-cwe190-s02": Path("my_cases/buffer + integer/CWE190_Integer_Overflow/s02"),
    "integer-taint-cwe190-s03": Path("my_cases/integer + taint/CWE190_Integer_Overflow/s03"),
    "integer-taint-cwe191-s03": Path("my_cases/integer + taint/CWE191_Integer_Underflow/s03"),
    "taint-buffer-cwe121-s01": Path("my_cases/taint + buffer/CWE121_Stack_Based_Buffer_Overflow/s01"),
    "taint-buffer-cwe122-s01": Path("my_cases/taint + buffer/CWE122_Heap_Based_Buffer_Overflow/s01"),
    "taint-buffer-cwe129-fgets-s01": Path("my_cases/taint + buffer/CWE121_Stack_Based_Buffer_Overflow/s01"),
    "taint-buffer-trimmed": Path("my_cases/taint+buffer_trimmed"),
    "taint-controlflow-cwe134-s01": Path("my_cases/taint + control flow/CWE134_Uncontrolled_Format_String/s01"),
}

# Generic fallback search roots, tried after the per-shard root.
GENERIC_ROOTS = [
    Path("."),
    Path("my_cases/testcasesupport"),
]

_resolve_cache: dict[tuple[str, str], Path | None] = {}


def _shard_key_from_sarif(sarif_path: Path | None) -> str:
    if sarif_path is None:
        return ""
    name = sarif_path.name  # e.g. taint-buffer-trimmed.combo-taint-buffer.sarif
    # Strip ".<suite>.sarif" from the right; suite labels never contain dots.
    stem = name[:-len(".sarif")] if name.endswith(".sarif") else name
    if "." in stem:
        stem = stem.rsplit(".", 1)[0]
    return stem


def resolve_artifact(uri: str, sarif_path: Path | None = None) -> Path | None:
    if not uri:
        return None
    key = (_shard_key_from_sarif(sarif_path), uri)
    if key in _resolve_cache:
        return _resolve_cache[key]
    p = Path(uri)
    result: Path | None = None
    if p.is_absolute() and p.exists():
        result = p
    else:
        roots: list[Path] = []
        shard_root = SHARD_ROOTS.get(key[0])
        if shard_root is not None:
            roots.append(shard_root)
        roots.extend(GENERIC_ROOTS)
        for root in roots:
            candidate = root / uri
            if candidate.exists():
                result = candidate
                break
    _resolve_cache[key] = result
    return result


_func_cache: dict[Path, list[tuple[int, str]]] = {}


def function_ranges(path: Path) -> list[tuple[int, str]]:
    """Return a sorted list of (start_line, function_name) for the file."""
    cached = _func_cache.get(path)
    if cached is not None:
        return cached

    ranges: list[tuple[int, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        _func_cache[path] = ranges
        return ranges

    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        if not line.strip() or line.lstrip().startswith(("//", "*", "/*", "#")):
            continue
        m = FUNC_DEF_RE.match(line)
        if not m:
            continue
        # Confirm next non-blank line is '{', so we skip forward
        # declarations that happen to lack a trailing semicolon.
        for j in range(i, min(i + 3, len(lines))):
            nxt = lines[j].strip()
            if not nxt:
                continue
            if nxt.startswith("{"):
                ranges.append((i, m.group(1)))
            break

    _func_cache[path] = ranges
    return ranges


def enclosing_function(path: Path, line: int) -> str | None:
    ranges = function_ranges(path)
    if not ranges:
        return None
    chosen: str | None = None
    for start, name in ranges:
        if start <= line:
            chosen = name
        else:
            break
    return chosen


def classify(func: str | None) -> str:
    """TP if the enclosing function name is a Juliet bad sink, FP if it is a
    Juliet good sink, and ? otherwise (shared helper, top-level, unknown)."""
    if not func:
        return "?"
    lower = func.lower()
    has_bad = "bad" in lower
    has_good = "good" in lower
    if has_bad and not has_good:
        return "TP"
    if has_good and not has_bad:
        return "FP"
    return "?"


def summarize(path: Path) -> int:
    with path.open(encoding="utf-8") as f:
        sarif = json.load(f)

    run = sarif["runs"][0]
    results = run.get("results", [])
    rules = {rule["id"]: rule for rule in run["tool"]["driver"].get("rules", [])}

    classified: list[tuple[str, str, str, int, str]] = []
    # (label, rule_id, artifact, line, func)
    for result in results:
        loc = result.get("locations", [{}])[0].get("physicalLocation", {})
        artifact = loc.get("artifactLocation", {}).get("uri", "")
        line = loc.get("region", {}).get("startLine", 0) or 0
        resolved = resolve_artifact(artifact, path)
        func = enclosing_function(resolved, line) if (resolved and line) else None
        label = classify(func)
        classified.append((label, result.get("ruleId", ""), artifact, line, func or ""))

    label_counts = Counter(label for label, *_ in classified)
    total = len(results)
    tp = label_counts.get("TP", 0)
    fp = label_counts.get("FP", 0)
    unk = label_counts.get("?", 0)
    precision_basis = tp + fp
    precision = (tp / precision_basis * 100.0) if precision_basis else 0.0

    print(f"\n{path}")
    print(f"  tool: {run['tool']['driver'].get('name')} {run['tool']['driver'].get('semanticVersion')}")
    print(f"  results: {total}   TP: {tp}   FP: {fp}   ?: {unk}   "
          f"precision (TP/(TP+FP)): {precision:.1f}%")

    # Per-rule breakdown with TP / FP / ?
    by_rule: dict[str, Counter] = defaultdict(Counter)
    for label, rule_id, *_ in classified:
        by_rule[rule_id][label] += 1

    print(f"  {'count':>5} {'TP':>4} {'FP':>4} {'?':>4}  rule")
    for rule_id, counts in sorted(
        by_rule.items(),
        key=lambda kv: (-sum(kv[1].values()), kv[0]),
    ):
        rule = rules.get(rule_id, {})
        name = rule.get("shortDescription", {}).get("text", "")
        total_r = sum(counts.values())
        print(f"  {total_r:>5} {counts['TP']:>4} {counts['FP']:>4} {counts['?']:>4}  "
              f"{rule_id}  {name}")

    # Per-finding listing
    for index, (label, rule_id, artifact, line, func) in enumerate(classified, 1):
        print(f"    {index:>4}. [{label:>2}] {rule_id} {artifact}:{line}  "
              f"({func or 'no-enclosing-function'})")

    return total


def count_expected_in_corpus(corpus: Path, restrict_to: set[Path] | None = None) -> tuple[int, int]:
    """Walk `corpus` and count Juliet-labelled functions.

    Returns (num_bad, num_good), i.e. ground-truth TP and TN sites. Each
    function is counted once. Functions whose names contain neither 'bad'
    nor 'good' (helpers, main, etc.) are ignored.

    If `restrict_to` is given, only consider source files in that set.
    Used to scope recall to the files the analysed database actually
    contains, not the full corpus on disk.
    """
    bad = 0
    good = 0
    if restrict_to is not None:
        sources = list(restrict_to)
    else:
        sources = list(corpus.rglob("*.c")) + list(corpus.rglob("*.cpp")) + list(corpus.rglob("*.cc"))
    for src in sources:
        for _start, name in function_ranges(src):
            label = classify(name)
            if label == "TP":
                bad += 1
            elif label == "FP":
                good += 1
    return bad, good


def sarif_artifact_paths(sarif_paths: list[Path]) -> set[Path]:
    """Union of source files referenced by *results* across all given SARIFs.

    We ignore the run.artifacts[] metadata because CodeQL records every
    file in --source-root there, including files the build command never
    compiled. That would inflate the recall denominator. Result locations
    only appear for files the database actually analysed.
    """
    files: set[Path] = set()
    for sp in sarif_paths:
        try:
            with sp.open(encoding="utf-8") as f:
                sarif = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        run = sarif["runs"][0]
        for r in run.get("results", []):
            uri = (
                r.get("locations", [{}])[0]
                .get("physicalLocation", {})
                .get("artifactLocation", {})
                .get("uri", "")
            )
            if not uri:
                continue
            resolved = resolve_artifact(uri, sp)
            if resolved is not None and resolved.suffix in {".c", ".cpp", ".cc"}:
                files.add(resolved)
    return files


def classify_results(path: Path) -> tuple[Counter, set[tuple[str, str]]]:
    """Return (label_counts, set of (file, bad_function) tuples actually flagged).
    The second value is used as the numerator for recall."""
    with path.open(encoding="utf-8") as f:
        sarif = json.load(f)
    run = sarif["runs"][0]
    counts: Counter = Counter()
    flagged_bad: set[tuple[str, str]] = set()
    for result in run.get("results", []):
        loc = result.get("locations", [{}])[0].get("physicalLocation", {})
        artifact = loc.get("artifactLocation", {}).get("uri", "")
        line = loc.get("region", {}).get("startLine", 0) or 0
        resolved = resolve_artifact(artifact, path)
        func = enclosing_function(resolved, line) if (resolved and line) else None
        label = classify(func)
        counts[label] += 1
        if label == "TP" and func:
            flagged_bad.add((artifact, func))
    return counts, flagged_bad


def compare(corpus_arg: str, sarif_args: list[str]) -> int:
    corpus = Path(corpus_arg)
    if not corpus.exists():
        print(f"corpus not found: {corpus}", file=sys.stderr)
        return 2
    # Scope ground-truth counting to files the SARIFs actually reference,
    # so recall is computed against what the database saw, not against every
    # .c file sitting under `corpus` on disk.
    analyzed = sarif_artifact_paths([Path(a) for a in sarif_args])
    if analyzed:
        bad_total, good_total = count_expected_in_corpus(corpus, restrict_to=analyzed)
        scope = f"{len(analyzed)} analyzed file(s)"
    else:
        bad_total, good_total = count_expected_in_corpus(corpus)
        scope = "full corpus walk (no artifacts in SARIF)"
    print(f"\nCorpus: {corpus}")
    print(f"  ground truth ({scope}): bad-functions={bad_total}  good-functions={good_total}")

    header = f"  {'suite':<32} {'results':>8} {'TP':>5} {'FP':>5} {'?':>5}  {'precision':>10}  {'recall':>8}"
    print()
    print(header)
    print("  " + "-" * (len(header) - 2))
    for arg in sarif_args:
        path = Path(arg)
        counts, flagged_bad = classify_results(path)
        tp = counts["TP"]
        fp = counts["FP"]
        unk = counts["?"]
        total = tp + fp + unk
        prec = (tp / (tp + fp) * 100.0) if (tp + fp) else 0.0
        rec = (len(flagged_bad) / bad_total * 100.0) if bad_total else 0.0
        # Suite label from the SARIF filename: <shard>.<suite>.sarif -> <suite>
        stem = path.name[:-len(".sarif")] if path.name.endswith(".sarif") else path.name
        suite = stem.rsplit(".", 1)[1] if "." in stem else stem
        print(f"  {suite:<32} {total:>8} {tp:>5} {fp:>5} {unk:>5}  {prec:>9.1f}%  {rec:>7.1f}%")
    return 0


def main() -> int:
    if len(sys.argv) >= 4 and sys.argv[1] == "--compare":
        return compare(sys.argv[2], sys.argv[3:])

    if len(sys.argv) < 2:
        print(
            "usage:\n"
            "  summarize_sarif.py <file.sarif> [file.sarif ...]\n"
            "  summarize_sarif.py --compare <corpus_dir> <file.sarif> [file.sarif ...]",
            file=sys.stderr,
        )
        return 2

    grand_total = 0
    grand_tp = 0
    grand_fp = 0
    grand_unk = 0

    for arg in sys.argv[1:]:
        path = Path(arg)
        with path.open(encoding="utf-8") as f:
            sarif = json.load(f)
        run = sarif["runs"][0]
        results = run.get("results", [])
        for result in results:
            loc = result.get("locations", [{}])[0].get("physicalLocation", {})
            artifact = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", 0) or 0
            resolved = resolve_artifact(artifact, path)
            func = enclosing_function(resolved, line) if (resolved and line) else None
            label = classify(func)
            grand_total += 1
            if label == "TP":
                grand_tp += 1
            elif label == "FP":
                grand_fp += 1
            else:
                grand_unk += 1
        summarize(path)

    if len(sys.argv) > 2:
        precision_basis = grand_tp + grand_fp
        precision = (grand_tp / precision_basis * 100.0) if precision_basis else 0.0
        print(
            f"\nOVERALL: results: {grand_total}   TP: {grand_tp}   "
            f"FP: {grand_fp}   ?: {grand_unk}   "
            f"precision: {precision:.1f}%"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
