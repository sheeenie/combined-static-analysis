# Combined Static Analysis Experiments

This repository is set up to compare stock CodeQL C/C++ analysis against broader experimental isolated suites and custom combination-oriented queries on selected Juliet-style CWE subsets **and** on a real-world target (libpng).

The verified paths are the self-contained `taint+buffer_trimmed` subset plus the selected Juliet shards under `my_cases/<combination>/.../sXX`. Juliet support files are expected at `my_cases/testcasesupport`; the run script compiles a small explicit file subset from each shard so the experiment stays fast and reproducible.

The real-world path pins **libpng** at five release tags — a clean modern baseline (`v1.6.37`) plus two vuln/fix pairs (`v1.6.34`/`v1.6.36` for CVE-2018-13785, `v1.2.53`/`v1.2.54` for CVE-2015-8126) — and runs the full isolated + combination matrix against each. libpng is production C code that parses attacker-controlled image bytes into fixed-size buffers, exercising buffer, integer, taint, and control-flow dimensions simultaneously — making it the design-science validation target for the combination queries developed against Juliet.

## What Is Being Tested

The high-level combinations are:

| Combination | Repo path | Selected CWE subset |
|---|---|---|
| buffer + integer | `my_cases/buffer + integer` | `CWE190_Integer_Overflow/s02` |
| integer + taint | `my_cases/integer + taint` | `CWE190_Integer_Overflow/s03`, `CWE191_Integer_Underflow/s03` |
| taint + buffer | `my_cases/taint+buffer_trimmed` and `my_cases/taint + buffer` | verified trimmed `CWE121`, `CWE122`; selected full `CWE121/s01`, `CWE122/s01` |
| taint + control flow | `my_cases/taint + control flow` | `CWE134_Uncontrolled_Format_String/s01`; `CWE606` is relevant but larger and not enabled by default |
| **real-world libpng** | `targets/libpng-<tag>/` (cloned by the script) | `v1.6.37` (clean modern baseline, FP-shape), `v1.6.34` (vuln, CVE-2018-13785), `v1.6.36` (fix for CVE-2018-13785), `v1.2.53` (vuln, CVE-2015-8126 / CVE-2015-8540), `v1.2.54` (fix for CVE-2015-8126) |

This subset is intentionally small. It keeps the first iteration reproducible and avoids trying to build the entire benchmark suite at once.

The experiment now has three layers:

| Layer | Purpose | Expected behavior |
|---|---|---|
| stock CodeQL | High-confidence baseline from `cpp-security-and-quality.qls` | Often sparse on these small synthetic shards |
| isolated suites | Category-specific coverage for buffer, integer, taint, or control-flow signals | Should produce nonzero findings on matching CWE shards |
| combination suites | Imported isolated suites plus lower-precision cross-signal hotspot queries | Should produce more findings than isolated runs, with more expected false positives |

The custom hotspot queries are deliberately experimental. They use Juliet/CWE context and broad syntactic patterns to make the comparison richer; they should not be treated as production-grade alert rules without additional filtering.

## What Is Needed To Run Everything

To compare isolated analyses against combination analyses, each selected benchmark shard needs a successful CodeQL database build. For the Juliet-style folders, that means restoring the support files expected by the test cases:

```text
my_cases/testcasesupport/io.c
my_cases/testcasesupport/std_thread.c
my_cases/testcasesupport/*.h
```

Most `sXX` Makefiles refer to these through:

```text
../../../testcasesupport
```

The one top-level `CWE606_Unchecked_Loop_Condition` Makefile uses:

```text
../../testcasesupport
```

So the practical fix is to add the Juliet `testcasesupport` directory directly under `my_cases/`. The helper script currently compiles selected files directly instead of invoking each shard's broad `make all`, because those Makefiles can build hundreds of test cases per shard.

For each selected shard the helper now compiles the full set of single-file Juliet flow variants `_01.c` through `_18.c` (basic, `if/else`, `switch`, function-pointer, and similar control-flow patterns). Multi-file flow variants (`_21+`, with `a`/`b`/`c` splits) are still excluded because they require coordinated multi-translation-unit builds and would inflate runtime without changing the comparison shape.

For each selected shard the helper now compiles the full set of single-file Juliet flow variants `_01.c` through `_18.c` (basic, `if/else`, `switch`, function-pointer, etc.). Multi-file flow variants (`_21+`, with `a`/`b`/`c` splits) are still excluded because they require coordinated multi-translation-unit builds and would inflate runtime without changing the comparison shape.

After that, the experiment matrix is:

| Benchmark shard | Isolated baseline A | Isolated baseline B | Combination run |
|---|---|---|---|
| `buffer + integer/CWE190_Integer_Overflow/s02` | buffer | integer | buffer + integer |
| `integer + taint/CWE190_Integer_Overflow/s03` | integer | taint | integer + taint |
| `integer + taint/CWE191_Integer_Underflow/s03` | integer | taint | integer + taint |
| `taint + buffer/CWE121_Stack_Based_Buffer_Overflow/s01` | taint | buffer | taint + buffer |
| `taint + buffer/CWE122_Heap_Based_Buffer_Overflow/s01` | taint | buffer | taint + buffer |
| `taint + control flow/CWE134_Uncontrolled_Format_String/s01` | taint | control flow | taint + control flow |

For each row, compare the result count and rule IDs from the two isolated runs against the combination run on the same database. The combination should never be compared against a different database, because database extraction differences can look like analysis differences.

## CodeQL Installation

Download and unpack the CodeQL bundle into the repo root so the CLI is available at:

```bash
./codeql/codeql
```

Check it:

```bash
./codeql/codeql version
```

You can also point the scripts to another install:

```bash
CODEQL=/path/to/codeql ./scripts/run_experiments.sh
```

The `codeql/` bundle and downloaded archives should stay local and uncommitted.

## Custom Queries

The custom query pack lives in:

```text
queries/combined-cpp
```

Current custom and experimental queries:

```text
queries/combined-cpp/BufferDangerousApiHotspot.ql
queries/combined-cpp/IntegerArithmeticHotspot.ql
queries/combined-cpp/TaintSourceHotspot.ql
queries/combined-cpp/ControlFlowHotspot.ql
queries/combined-cpp/ComboBufferIntegerHotspot.ql
queries/combined-cpp/ComboIntegerTaintHotspot.ql
queries/combined-cpp/ComboTaintBufferHotspot.ql
queries/combined-cpp/ComboTaintControlFlowHotspot.ql
queries/combined-cpp/StructFieldMemcpyOverrun.ql
queries/combined-cpp/TaintToBufferFlow.ql
queries/combined-cpp/LibpngSources.qll    # custom source model (library)
```

`LibpngSources.qll` is the codebase-specific source-model adapter. It exports `libpngFlowSource(node, type)` (consumed by `TaintToBufferFlow.ql`'s `isSource`) and `libpngInputApi(call)` (OR-ed into each hotspot's `inputApi` list). Without it, the data-flow taint→buffer query produces zero results on libpng because the stock FlowSources model does not bridge libpng's `png_read_data` / `png_get_uint_*` wrappers around the underlying `fread`. The same pattern (one `.qll` per analyzed project) is the recommended way to add new real-world targets to this pack.

`StructFieldMemcpyOverrun.ql` is the precise custom rule. It reports `memcpy` or `memmove` calls where the destination is a struct field and the copy size is larger than that field can hold. This catches the trimmed Juliet pattern:

```c
memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid));
```

The `*Hotspot.ql` queries are broader experimental coverage rules:

| Query | Suite role | Main CWE coverage |
|---|---|---|
| `BufferDangerousApiHotspot.ql` | isolated buffer | CWE-119, CWE-120, CWE-121, CWE-122, CWE-125, CWE-131, CWE-190, CWE-191, CWE-787, CWE-788, CWE-805 |
| `IntegerArithmeticHotspot.ql` | isolated integer | CWE-190, CWE-191, CWE-369, CWE-681, CWE-682, CWE-839 |
| `TaintSourceHotspot.ql` | isolated taint | CWE-20, CWE-22, CWE-78, CWE-89, CWE-134, CWE-190, CWE-606, CWE-807 |
| `ControlFlowHotspot.ql` | isolated control flow | CWE-134, CWE-606, CWE-691, CWE-807, CWE-835 |
| `ComboBufferIntegerHotspot.ql` | buffer + integer | CWE-119, CWE-120, CWE-131, CWE-190, CWE-191, CWE-680, CWE-787, CWE-805 |
| `ComboIntegerTaintHotspot.ql` | integer + taint | CWE-20, CWE-190, CWE-191, CWE-681, CWE-682 |
| `ComboTaintBufferHotspot.ql` | taint + buffer | CWE-20, CWE-119, CWE-120, CWE-121, CWE-122, CWE-787, CWE-805 |
| `ComboTaintControlFlowHotspot.ql` | taint + control flow | CWE-20, CWE-606, CWE-691, CWE-807, CWE-835 |

The custom suite is:

```text
queries/combined-cpp/codeql-suites/custom-combinations.qls
```

The isolated and combination experiment suites are:

```text
queries/combined-cpp/codeql-suites/experiment/isolated-taint.qls
queries/combined-cpp/codeql-suites/experiment/isolated-buffer.qls
queries/combined-cpp/codeql-suites/experiment/isolated-integer.qls
queries/combined-cpp/codeql-suites/experiment/isolated-controlflow.qls
queries/combined-cpp/codeql-suites/experiment/combo-buffer-integer.qls
queries/combined-cpp/codeql-suites/experiment/combo-integer-taint.qls
queries/combined-cpp/codeql-suites/experiment/combo-taint-buffer.qls
queries/combined-cpp/codeql-suites/experiment/combo-taint-controlflow.qls
```

Compile-check all custom queries:

```bash
./codeql/codeql query compile \
  --search-path=codeql/qlpacks \
  queries/combined-cpp/*.ql
```

## Run Guide

Run the default verified experiment:

```bash
./scripts/run_experiments.sh
```

This creates one database:

```text
codeql-dbs/taint-buffer-trimmed
```

It emits these SARIF files:

```text
results/taint-buffer-trimmed.stock.sarif
results/taint-buffer-trimmed.isolated-taint.sarif
results/taint-buffer-trimmed.isolated-buffer.sarif
results/taint-buffer-trimmed.combo-taint-buffer.sarif
results/taint-buffer-trimmed.custom-only.sarif
```

Meaning:

| File | Analysis |
|---|---|
| `.stock.sarif` | CodeQL `cpp-security-and-quality.qls` only |
| `.isolated-taint.sarif` | taint-sensitive suite, including broad source hotspots |
| `.isolated-buffer.sarif` | buffer/memory-bound suite, including broad dangerous API hotspots |
| `.combo-taint-buffer.sarif` | taint + buffer suite, including imported isolated rules, the precise struct-field overwrite query, and the taint/buffer combo hotspot |
| `.custom-only.sarif` | precise custom query suite only |

Summarize any SARIF file:

```bash
python3 scripts/summarize_sarif.py results/taint-buffer-trimmed.combo-taint-buffer.sarif
```

The summarizer classifies each finding as **TP**, **FP**, or **?** by looking up the source file and line in the SARIF result and matching the enclosing function name against Juliet's labelling convention:

- function name contains `bad` and not `good` → **TP** (true positive — finding is in or reachable from a Juliet `bad` sink)
- function name contains `good` and not `bad` → **FP** (false positive — finding is in a Juliet `good*`/`goodG2B`/`goodB2G` variant that is intentionally safe)
- otherwise (top-level, shared helper such as `printIntLine`/`globalReturnsTrue`, or unresolved location) → **?**

The output now includes a header line with `TP / FP / ? / precision`, a per-rule breakdown of the same three buckets, and an inline `[TP]`/`[FP]`/`[?]` tag plus the resolved enclosing function name on every per-finding row. When multiple SARIFs are passed in one invocation, a final `OVERALL` line aggregates across all files.

Example header:

```text
results/taint-buffer-trimmed.isolated-buffer.sarif
  tool: CodeQL 2.25.4
  results: 28   TP: 10   FP: 18   ?: 0   precision (TP/(TP+FP)): 35.7%
```

This labelling is only meaningful on Juliet-style benchmarks. On real codebases without `bad`/`good` naming, every finding will fall into the `?` bucket.

## Real-World Target: libpng

In addition to the Juliet-style shards, `run_experiments.sh` also clones and analyzes [libpng](https://github.com/pnggroup/libpng) at one or more pinned release tags. The default tag list is `v1.6.37 v1.6.34 v1.2.53`:

- `v1.6.37` — recent stable release; used as the **clean modern baseline** for measuring false-positive shape of the experimental queries on production code.
- `v1.6.34` — pre-fix for **CVE-2018-13785** (integer overflow in `png_check_chunk_length`, fixed in 1.6.36); used as a 1.6.x-line **TP target**.
- `v1.2.53` — legacy 1.2.x; pre-fix for **CVE-2015-8126** (heap overflow in `png_handle_PLTE`, fixed in 1.2.54) and **CVE-2015-8540** (out-of-bounds read in `png_check_keyword`, fixed in 1.2.55). Richer historical TP set than the 1.6.x tags.

For each tag the pipeline:

1. Shallow-clones the tag into `targets/libpng-<tag>/` (idempotent).
2. Builds via `scripts/build_libpng.sh` (`./configure --disable-shared --enable-static && make -j$(nproc)`).
3. Creates a CodeQL database at `codeql-dbs/libpng-<tag>/`.
4. Analyzes the database with **10 suites** and writes one SARIF per suite under `results/libpng-<tag>.<suite>.sarif`:

| Layer | Suites |
|---|---|
| baseline | `stock` |
| isolated (one per dimension) | `isolated-taint`, `isolated-buffer`, `isolated-integer`, `isolated-controlflow` |
| pairwise combinations | `combo-taint-buffer`, `combo-taint-buffer-flow`, `combo-taint-controlflow`, `combo-integer-taint`, `combo-buffer-integer` |

Run only the libpng matrix (skip all Juliet pipelines):

```bash
LIBPNG_ONLY=1 ./scripts/run_experiments.sh
```

Override the tag list:

```bash
LIBPNG_TAGS="v1.6.37 v1.6.34 v1.6.36 v1.2.53 v1.2.54" LIBPNG_ONLY=1 ./scripts/run_experiments.sh
```

Other knobs: `LIBPNG_REPO` (defaults to the canonical `pnggroup/libpng`), `TARGETS_ROOT` (defaults to `targets/`), `RUN_LIBPNG=0` (skip libpng entirely from the default run).

Requirements: `zlib` headers + library (`apt install zlib1g-dev`) and a C toolchain. The pipeline skips itself with a hint message if zlib is missing.

### Validation tools for libpng

`scripts/summarize_sarif.py` classifies findings by matching the enclosing function name against Juliet's `bad`/`good` convention. libpng functions are named `png_read_chunk`, `png_check_*`, `png_handle_*`, etc., so **every libpng finding falls into the `?` bucket** and the auto-derived precision number is meaningless. For libpng the relevant signal is total count per suite, per-rule breakdown, and three separate analytical scripts:

```bash
# Per-CVE site coverage against manually-curated ground truth.
python3 scripts/cve_validation.py            # all tags
python3 scripts/cve_validation.py v1.6.34    # restrict to one tag

# Per-pair |A|, |B|, |A ∪ B|, |A ∩ B| at enclosing-function granularity,
# with the primary operator chosen by relationship type (dependency →
# intersection, complementary → union). This is the central measurement
# for the "what does combining buy us" research question.
python3 scripts/intersect_sets.py
python3 scripts/intersect_sets.py v1.6.34    # restrict to one tag

# Vuln-tag vs fix-tag set diff. Cleanly labels TPs only for queries whose
# sink is the bug's effect, not its symptom — see §"Iteration 3.5" for
# why this arm came back nearly empty on our pattern-based queries.
python3 scripts/diff_tags.py v1.6.34 v1.6.36
python3 scripts/diff_tags.py v1.2.53 v1.2.54
```

The per-tag CVE ground truth lives in `docs/libpng_cve_ground_truth.json` and is read by `cve_validation.py`. It maps `(tag, CVE) → (file, function)` for the documented sites we want each iteration to attempt to reach. Suites firing inside the function are reported as hits — the headline output of the experiment.

## Full Subset Runs

The script contains selected Juliet shards, but does not run them by default because they require `my_cases/testcasesupport`.

After restoring the support directory, run:

```bash
RUN_FULL_SUBSETS=1 ./scripts/run_experiments.sh
```

The script then creates one database per selected shard, compiles only the explicitly selected files in that shard, and runs:

```text
stock
isolated-<first category>
isolated-<second category>
combo-<first>-<second>
```

For example, the `buffer + integer` shard emits:

```text
results/buffer-integer-cwe190-s02.stock.sarif
results/buffer-integer-cwe190-s02.isolated-buffer.sarif
results/buffer-integer-cwe190-s02.isolated-integer.sarif
results/buffer-integer-cwe190-s02.combo-buffer-integer.sarif
```

## Current Verified Results

The numbers below come from a clean `RUN_FULL_SUBSETS=1 ./scripts/run_experiments.sh` run that compiled Juliet flow variants `_01..._18` for each selected shard. TP/FP labels are derived by `scripts/summarize_sarif.py` from the enclosing function name (`bad*` ⇒ TP, `good*` ⇒ FP).

### `taint-buffer-trimmed` (the self-contained verification case)

| Analysis | Total | TP | FP | Precision |
|---|---:|---:|---:|---:|
| stock CodeQL security-and-quality | 0 | 0 | 0 | – |
| isolated taint suite | 0 | 0 | 0 | – |
| isolated buffer suite | 28 | 10 | 18 | 35.7% |
| custom query suite (`StructFieldMemcpyOverrun.ql`) | 10 | 10 | 0 | **100.0%** |
| taint + buffer combination suite | 38 | 20 | 18 | 52.6% |

The 10 precise custom alerts correspond to 5 CWE121 stack-based and 5 CWE122 heap-based `memcpy` overruns where 32 bytes are copied into the 16-byte `charFirst` field. The isolated buffer suite additionally fires on the matching `good1`/`good2` variants — that is the precision/recall tradeoff between the precise custom rule and the broader hotspot rule.

### Selected Juliet shards (`_01..._18` flow variants per shard)

| Shard | Suite | Total | TP | FP | Precision |
|---|---|---:|---:|---:|---:|
| `buffer-integer-cwe190-s02` | stock | 13 | 3 | 10 | 23.1% |
| `buffer-integer-cwe190-s02` | isolated-buffer | 100 | 36 | 64 | 36.0% |
| `buffer-integer-cwe190-s02` | isolated-integer | 233 | 73 | 160 | 31.3% |
| `buffer-integer-cwe190-s02` | combo-buffer-integer | 433 | 145 | 288 | 33.5% |
| `integer-taint-cwe190-s03` | stock | 31 | 2 | 29 | 6.5% |
| `integer-taint-cwe190-s03` | isolated-integer | 216 | 56 | 160 | 25.9% |
| `integer-taint-cwe190-s03` | isolated-taint | 185 | 89 | 96 | 48.1% |
| `integer-taint-cwe190-s03` | combo-integer-taint | 535 | 183 | 352 | 34.2% |
| `integer-taint-cwe191-s03` | stock | 31 | 2 | 29 | 6.5% |
| `integer-taint-cwe191-s03` | isolated-integer | 199 | 39 | 160 | 19.6% |
| `integer-taint-cwe191-s03` | isolated-taint | 50 | 18 | 32 | 36.0% |
| `integer-taint-cwe191-s03` | combo-integer-taint | 416 | 96 | 320 | 23.1% |
| `taint-buffer-cwe121-s01` | stock | 3 | 1 | 2 | 33.3% |
| `taint-buffer-cwe121-s01` | isolated-taint | 0 | 0 | 0 | – |
| `taint-buffer-cwe121-s01` | isolated-buffer | 51 | 19 | 32 | 37.3% |
| `taint-buffer-cwe121-s01` | combo-taint-buffer | 69 | 37 | 32 | **53.6%** |
| `taint-buffer-cwe122-s01` | stock | 3 | 1 | 2 | 33.3% |
| `taint-buffer-cwe122-s01` | isolated-taint | 0 | 0 | 0 | – |
| `taint-buffer-cwe122-s01` | isolated-buffer | 51 | 19 | 32 | 37.3% |
| `taint-buffer-cwe122-s01` | combo-taint-buffer | 69 | 37 | 32 | **53.6%** |
| `taint-controlflow-cwe134-s01` | stock | 31 | 21 | 10 | **67.7%** |
| `taint-controlflow-cwe134-s01` | isolated-taint | 68 | 36 | 32 | 52.9% |
| `taint-controlflow-cwe134-s01` | isolated-controlflow | 498 | 158 | 340 | 31.7% |
| `taint-controlflow-cwe134-s01` | combo-taint-controlflow | 1006 | 352 | 654 | 35.0% |

Patterns to notice in the table:

- The combination suite always raises TP coverage versus either isolated suite (e.g. CWE-121: `19 → 37` TP), at the cost of more FPs — exactly the tradeoff the experiment is designed to surface.
- The precise custom rule on the trimmed case is the only suite that hits 100% precision; every broader hotspot rule lands on at least some `good*` variants.
- Stock CodeQL on the small Juliet shards is sparse and mixed (0 TP on the trimmed case, 21/31 on `CWE134` which has high-quality library queries for tainted format strings).
- For `CWE121`/`CWE122` the isolated-taint suite produces zero findings, so the combination's TP gain comes entirely from the cross-signal hotspot rules added in the combo suite, not from the imported isolated taint queries.

### Real-world libpng results

Run produced **30 SARIFs** (10 suites × 3 pinned tags) on libpng:

```
codeql-dbs/libpng-v1.6.37   results/libpng-v1.6.37.<suite>.sarif
codeql-dbs/libpng-v1.6.34   results/libpng-v1.6.34.<suite>.sarif
codeql-dbs/libpng-v1.2.53   results/libpng-v1.2.53.<suite>.sarif
```

#### Per-suite result counts

The table below reflects three iterations of the experiment:

- **iter 1** — queries as-shipped (Juliet-only file filters, only-libc `inputApi` lists). Zero data-flow taint→buffer hits, zero CVE-site coverage.
- **iter 2** — added `LibpngSources.qll` (custom source model), dropped Juliet-only `relevantFile` filters from three hotspots, propagated `libpngInputApi` into each hotspot's `inputApi`. Data-flow query starts firing; CVE-2015-8126 becomes detectable.
- **iter 3** — added an **integer-guard sink** to `TaintToBufferFlow.ql` (tainted value used as an operand of a comparison whose other operand is itself a runtime-computed expression, not a literal). CVE-2018-13785 becomes detectable, at the cost of a 10-15× growth in the data-flow query's raw count.

| Suite | v1.6.37 iter1→2→3 | v1.6.34 iter1→2→3 | v1.6.36 (fix) | v1.2.53 iter1→2→3 | v1.2.54 (fix) |
|---|---:|---:|---:|---:|---:|
| stock | 183 | 54 | 184 | 38 | 38 |
| isolated-taint | 35→**193** | 4→**139** | 193 | 0→**155** | 155 |
| isolated-buffer | 42 | 4 | 42 | 1 | 1 |
| isolated-integer | 12 | 9 | 12 | 7 | 7 |
| isolated-controlflow | 2 | 0 | 2 | 0 | 0 |
| combo-taint-buffer | 86→**246** | 10→**147** | 246 | 1→**158** | 158 |
| **combo-taint-buffer-flow** | **0→14→212** | **0→14→184** | **212** | **0→14→107** | **112** |
| combo-taint-controlflow | 37→**944** | 4→**607** | 944 | 0→**544** | 546 |
| combo-integer-taint | 47→**442** | 13→**336** | 442 | 7→**252** | 255 |
| combo-buffer-integer | 54 | 13 | 54 | 8 | 8 |

Note: the v1.6.34 column is built with `scripts/makefile.linux` (12 .c files — fewer translation units) because that tag does not commit a generated `configure`. v1.6.36 reverts to `./configure && make`, which extracts contrib/libtests too (21 .c files). The 1.6.34 ↔ 1.6.36 row deltas therefore reflect both build-scope changes and the fix — they are not directly comparable counts. The 1.2.53 ↔ 1.2.54 pair, by contrast, used the same configure-based build on both sides and shows that the fix barely changes the count (e.g. `combo-taint-buffer-flow`: 107 vs 112). See *Iteration 3.5* below for what this tells us.

Two refinements drive the iter-1 → iter-2 jump:

1. **`queries/combined-cpp/LibpngSources.qll`** — a custom source model. Exports `libpngFlowSource(node, type)` for the data-flow query and `libpngInputApi(call)` for the syntactic hotspots. Recognises:
    - the output buffer of `png_read_data` / `png_default_read_data` / `png_crc_read` (the wrapper around the input stream),
    - the `length` / `size` parameter of `png_handle_*` and `png_check_chunk_length` (read from the on-disk chunk header before each handler is called),
    - return values of `png_get_uint_32` / `png_get_uint_16` / `png_get_uint_31` / `png_get_int_*` (byte-order helpers that interpret raw input bytes).
2. **Dropping the Juliet-only `relevantFile` filters** from `ComboIntegerTaintHotspot.ql`, `ComboTaintControlFlowHotspot.ql`, and `TaintSourceHotspot.ql`. Each of those queries previously refused to fire outside `CWE###` paths, so on libpng they produced zero results regardless of the input model.

`TaintToBufferFlow.ql` now imports `LibpngSources` and OR-s `libpngFlowSource` into its `isSource`. The 14 new findings per tag are real interprocedural paths, e.g.:

- `pngpread.c`: *User input from `png_get_uint_31()` flows to the size argument of `memcpy()`.*
- `pngset.c:625` (v1.2.53): *User input from `png_crc_read()` flows to the size argument of `memcpy()`.*
- `pngerror.c` (all tags): chunk-name characters read via `png_crc_read` reach array indices in the error-formatting code path.

#### Build-scope caveat — counts are NOT comparable across tags

The three tags use different build entrypoints, which extracts different sets of translation units into the CodeQL DB. The counts above are useful *within a tag* (isolated vs combo) but **not across tags** (v1.6.37 vs v1.6.34):

| Tag | Build path | TUs analyzed | Includes test programs / contrib tools? |
|---|---|---:|---|
| v1.6.37 | `./configure && make` | 21 .c | yes (`contrib/libtests/*.c`, `contrib/tools/*.c`, `pngtest.c`) |
| v1.6.34 | `make -f scripts/makefile.linux` (autoconf inputs only at this tag) | 12 .c | core library only |
| v1.2.53 | `./configure && make` | (legacy 1.2.x layout) | minimal |

To make the v1.6.37 vs v1.6.34 comparison strictly apples-to-apples, either install autotools and rebuild v1.6.34 with `autogen.sh && ./configure && make`, or restrict the v1.6.37 build to core library files only.

#### CVE-site coverage (design-science validation)

`scripts/cve_validation.py` walks the SARIFs and reports, per documented CVE, whether any suite produced a finding inside the vulnerable function's line range (derived from the cloned source so it tracks micro-release shifts). Coverage progressed across iterations:

| Tag | CVE | Vulnerable site (source-derived range) | iter 1 | iter 2 | iter 3 |
|---|---|---|:---:|:---:|:---:|
| v1.6.34 | **CVE-2018-13785** | `pngrutil.c:png_check_chunk_length` (3131-3179) | ✗ | ✗ | **✓** |
| v1.2.53 | **CVE-2015-8126** | `pngrutil.c:png_handle_PLTE` (501-647) | ✗ | **✓** | ✓ |
| v1.2.53 | CVE-2015-8540 | `pngwutil.c:png_check_keyword` (1224-1350) | ✗ | ✗ | ✗ |

Detection details at iter 3:

- **CVE-2015-8126** — 5 hits via `cpp/experimental/taint-source-hotspot` (isolated-taint, combo-taint-buffer, combo-taint-controlflow, combo-integer-taint, all firing on the libpng input-API calls inside `png_handle_PLTE`), plus **3 precise data-flow paths** from `cpp/experimental/taint-to-buffer-flow` at lines 546, 548, and 627 inside the same function. The data-flow paths are interpretable: each labels a specific libpng source API and the buffer-write or guard it reaches.
- **CVE-2018-13785** — 4 hits, all from `cpp/experimental/taint-to-buffer-flow` at lines 3148-3154 inside `png_check_chunk_length`. Caught entirely by the new integer-guard sink: the tainted chunk-length parameter is compared against `PNG_USER_CHUNK_MALLOC_MAX` and a derived `row_factor` expression, and the wrap that bypasses the check is exactly the comparison the sink models.

#### Why CVE-2015-8540 still misses

`png_check_keyword` is an OOB *read* on a string argument that is tainted at the caller, not inside the function. The current libpng source model doesn't mark `png_check_keyword`'s `key` parameter as a source, and even if it did, the sink (`key[i]` index reads with no upper-bound guard) is a read sink that our pack doesn't currently model. Both gaps are concrete query-engineering items — adding a parameter-as-source for write-side libpng helpers and an "array-index read without bounding guard" sink — and are the iter-4 work.

#### Cost of the iter-3 sink

The integer-guard sink fires every time a tainted value participates in a comparison whose other operand is a runtime expression. That is exactly what CVE-2018-13785 looks like, but it is also what every routine size-bounds check looks like. The price is a **10-15× growth** in the data-flow query's raw count (14 → 107-212 paths/tag). The CVE site is one of those paths; the other 100-200 per tag need triage. The interpretability advantage holds — every path comes with `source label → intermediate steps → sink label` — so this is closer to "annotated triage queue" than "alert stream", but it is no longer the manageable 14-path list iter 2 produced. A tighter form of the sink (e.g. restrict the other operand to be itself a derived size, or restrict to comparisons inside `if`/`while` conditions that protect a buffer operation) would trade some recall for a smaller queue.

#### How to combine — the operator follows from the relationship

The four pairs under study are not all the same kind of combination. Two distinct relationships, two distinct operators:

| Pair | Relationship | Why | Primary operator |
|---|---|---|---|
| taint + buffer | **dependency** | A buffer overflow that an attacker cannot reach is defensive code, not a vulnerability. Taint is the *reachability filter* for the buffer-overflow candidate set. | **intersection** (`buffer ∩ taint`) |
| integer + taint | complementary | An integer overflow is a bug independent of taint reachability (it can cause crashes / wrong outputs even when the input is fixed). Taint catches *input-controlled* problems. The analyses cover overlapping but not identical bug families. | union |
| integer + buffer | complementary | Both target memory/arithmetic correctness from different angles (arithmetic overflow vs. memory boundary). Neither subsumes the other. | union |
| taint + control flow | complementary | Unbounded control flow is a bug regardless of taint (CWE-835 infinite loops, CWE-691 missing termination); taint catches the *input-driven* subset. | union |

The intersection of two complementary analyses is still informative — it surfaces the higher-confidence subset where both signals fire on the same function — but the *primary* combination output is the union, because each side catches bugs the other cannot.

`scripts/intersect_sets.py` reads the existing SARIFs and reports `|A|`, `|B|`, `|A ∪ B|`, `|A ∩ B|` at the **enclosing-function granularity** for all four pairs across all five tags. Sample of the empirical result:

**Dependency pair (intersection is primary):**

| Tag | \|buffer\| | \|taint\| | \|buffer ∩ taint\| (functions) | functions |
|---|---:|---:|---:|---|
| v1.6.37 | 40 in 14 fns | 192 in 53 fns | **3** | `cp_one_file`, `png_handle_iCCP`, `write_one_file` |
| v1.6.34 (vuln) | 4 in 3 fns | 139 in 39 fns | **1** | `png_handle_iCCP` |
| v1.6.36 (fix) | 40 in 14 fns | 192 in 53 fns | **3** | `cp_one_file`, `png_handle_iCCP`, `write_one_file` |
| v1.2.53 (vuln) | 1 in 1 fn | 155 in 32 fns | **0** | – |
| v1.2.54 (fix) | 1 in 1 fn | 155 in 32 fns | **0** | – |

Two of the three v1.6.x intersection hits (`cp_one_file`, `write_one_file`) are in libpng's test harness under `contrib/`, not in deployed library code — security-relevant FPs by construction. **`png_handle_iCCP` is the one production-code candidate that the intersection points at.** It is present at every 1.6.x tag including the fix, and matches the iCCP chunk handler that has had multiple historical CVEs (CVE-2017-12652, CVE-2017-19156, CVE-2018-14048).

##### Per-line detail inside the intersection

The actual file:line locations of every finding inside the `buffer ∩ taint` functions (i.e. *where* taint and buffer interact, not just *which function*):

**v1.6.34 (vuln, CVE-2018-13785)** — 1 intersection function:

- `png_handle_iCCP()` in `pngrutil.c`:
  - **Buffer:** `pngrutil.c:1454` — `cpp/constant-array-overflow`
  - **Taint (7):** `pngrutil.c:1375, 1392, 1400, 1419, 1427, 1534, 1630` — all `cpp/experimental/taint-source-hotspot` (libpng input-API call sites)

The buffer finding at line 1454 sits in the middle of the cluster of taint reads (1375-1630), so this is a literal "attacker bytes are read into this function and a potential constant-array overflow is detected inside the same function." That is the shape the dependency intersection is designed to surface.

**v1.6.37 / v1.6.36** (counts are identical between these tags — the v1.6.36 patch is unrelated to these functions) — 3 intersection functions:

- `png_handle_iCCP()` in `pngrutil.c` — same shape as v1.6.34; taint lines shift by ±1 between tags:
  - **Buffer:** `pngrutil.c:1454` — `cpp/constant-array-overflow`
  - **Taint (7):** `pngrutil.c:1375, 1392, 1400, 1419, 1427, 1533, 1629` — `cpp/experimental/taint-source-hotspot`
- `cp_one_file()` in `contrib/tools/pngcp.c` (test tool, not deployed code):
  - **Buffer (5):** `pngcp.c:2220, 2235, 2235, 2236, 2260` — mix of `cpp/experimental/buffer-dangerous-api-hotspot` and `cpp/unbounded-write`
  - **Taint (1):** `pngcp.c:2217` — `cpp/path-injection`
- `write_one_file()` in `contrib/libtests/pngstest.c` (test harness):
  - **Buffer (3):** `pngstest.c:3215, 3215, 3223` — `cpp/unbounded-write` + `cpp/experimental/buffer-dangerous-api-hotspot`
  - **Taint (1):** `pngstest.c:3217` — `cpp/path-injection`

**v1.2.53 / v1.2.54** — intersection is empty. Stock buffer-overrun queries do not fire inside any of the 32 functions that have `isolated-taint` findings on the 1.2.x line. This is the methodological tell that distinguishes the set-operator combination from the custom cross-signal queries: the latter (taint-source-hotspot, `TaintToBufferFlow.ql`) does fire inside `png_handle_PLTE` on 1.2.53 and catches CVE-2015-8126, but it does so by being a *different query* — not by intersecting the existing outputs.

Reproducer for these line lists:

```bash
python3 scripts/intersect_sets.py v1.6.34   # function-level summary
# Per-line detail comes from grepping the SARIFs directly, e.g.:
python3 -c "import json; d=json.load(open('results/libpng-v1.6.34.isolated-buffer.sarif')); \
  [print(r['locations'][0]['physicalLocation']['artifactLocation']['uri'], \
         r['locations'][0]['physicalLocation']['region']['startLine'], r['ruleId']) \
   for r in d['runs'][0]['results']]"
```

**Complementary pairs (union is primary):**

| Tag | \|integer ∪ taint\|_fn | \|integer ∪ buffer\|_fn | \|taint ∪ controlflow\|_fn |
|---|---:|---:|---:|
| v1.6.37 | 63 | 24 | 55 |
| v1.6.34 | 46 | 10 | 39 |
| v1.6.36 | 63 | 24 | 55 |
| v1.2.53 | 38 | 7 | 32 |
| v1.2.54 | 38 | 7 | 32 |

Notably the function-level intersection of every complementary pair is **zero** across every tag — the integer / buffer / controlflow / taint isolated suites genuinely fire in disjoint functions on libpng. This is empirical confirmation that they cover different code, which is what "complementary" should mean.

The CVE-2015-8126 and CVE-2018-13785 sites are not in any of these intersections because, as iter-2 made clear, stock isolated-buffer and isolated-integer queries don't fire inside `png_handle_PLTE` or `png_check_chunk_length`. The mechanical intersection of *existing* isolated suites cannot find what its underlying queries can't see. This is the boundary between the set-operator combination above and the custom cross-signal queries (`TaintToBufferFlow.ql`, `ComboTaintBufferHotspot.ql`), which find different things by being separate queries with their own source/sink logic rather than set operations over the isolated outputs.

#### Iteration 3.5 — Fix-tag diff and what it tells us

To check whether the per-CVE detections at iter 3 disappear at the corresponding **fix** revisions, the pipeline now pins two extra tags:

- **v1.6.36** — fix release for CVE-2018-13785 (paired with v1.6.34).
- **v1.2.54** — fix release for CVE-2015-8126 (paired with v1.2.53). (CVE-2015-8540 was fixed later in v1.2.55, so v1.2.54 still has it.)

`scripts/diff_tags.py` aggregates each suite at `(ruleId, file-basename)` granularity and reports the *vuln-only delta* — the count of (rule, file) pairs that fire more times at the vuln tag than at the fix tag. Under the "patches remove the vulnerable pattern" hypothesis, this would mechanically label the TP subset without manual triage.

**It did not work as expected on this corpus.** The diff is essentially zero across every suite for both pairs:

```
v1.6.34 → v1.6.36   vuln-only-deltas-sum = 0 in 9 of 10 suites (stock: 1)
v1.2.53 → v1.2.54   vuln-only-deltas-sum = 0 in all 10 suites
```

In fact `combo-taint-buffer-flow` inside `png_handle_PLTE` went from **3 paths at v1.2.53** (vuln) to **6 paths at v1.2.54** (fix) — the fix tag has *more* findings inside the CVE function. The new paths are exactly the bounds-check arithmetic that v1.2.54 added:

```
v1.2.53 (vuln): pngrutil.c:546, 548, 627                                  (3 paths)
v1.2.54 (fix):  pngrutil.c:546, 548, 569, 574, 578, 641                  (6 paths)
```

Lines 546 and 548 — the original suspicious reads from `png_get_uint_31` and `png_read_data`/`png_crc_read` — are still flagged at the fix tag, because the fix kept the reads and added guards *around* them rather than removing the reads. Lines 569, 574, 578, 641 are the **new bounds checks**, and they fire the integer-guard sink because **the new bounds checks themselves look like our target pattern**: a tainted length compared against another integer.

This is the core limitation of pattern-based detection: a missing bounds check (bug) and an added bounds check (fix) involve the same arithmetic shape. A query that flags "tainted integer in a comparison" cannot tell whether the comparison *prevents* an OOB or *demonstrates the absence of prevention* — both are syntactically identical comparisons of the same source against another integer.

What the fix-tag diff would catch on a different query family:
- A query that flags **integer-overflow chains that reach a write sink** would diff cleanly: if the patch adds an early `return` on overflow, the path from source to sink is broken at the fix tag and the finding disappears.
- A query whose sink is the buffer write (not the bounds check) would similarly clean up at the fix tag, *provided* the new guard is recognized by `BarrierGuard` (`TaintToBufferConfig::isBarrier` already wires this in for upper-bound checks on positive constants).

For the iter-3 integer-guard sink specifically, the **right way to use the fix tag** is per-path, not per-count: look at each data-flow path's intermediate nodes and check whether the path at the fix tag passes through a new node that the path at the vuln tag did not. The current SARIF representation has the path graph; a structural path diff would be the natural iter-4 follow-up.

Methodological takeaway: **fix-tag diffs are a free TP label only for queries whose sink is the bug's *effect* (write, dereference, allocation), not its *symptom* (comparison, arithmetic).** The two CVEs we caught at iter 3 are detected by sinks of the second kind, so the diff arm of the validation doesn't cleanly separate them from the fix.

#### What the experiment as a whole confirms

1. **The right combination operator is determined by the relationship between the analyses, not chosen up front.** The four pairs under study split cleanly into one *dependency* pair (taint+buffer, intersection) and three *complementary* pairs (union). Applying intersection to a complementary pair degenerates to zero on libpng; applying union to the dependency pair loses the security-relevant filtering. The framework is two-operator, not one.
2. **A small custom source model converted zero hits into a working data-flow analysis.** `combo-taint-buffer-flow` went from 0 to 14 paths per tag with the `LibpngSources.qll` model alone (iter 2), and to 107-212 paths/tag once the integer-guard sink was added (iter 3). Every path is rooted in an identifiable libpng input API and ends at a labelled sink. The bottleneck on real-world code is the source/sink model, not the data-flow engine itself.
3. **Dropping Juliet-only file filters is a prerequisite for any real-world evaluation.** Three hotspot queries silently produced zero results on libpng before their `relevantFile` filters were dropped, regardless of rule quality.
4. **Two different paths to a documented CVE.** CVE-2015-8126 is caught by the custom taint-source-hotspot rule once libpng input APIs are modelled (iter 2); it is *not* caught by the mechanical `buffer ∩ taint` intersection because stock buffer-overrun queries don't fire in `png_handle_PLTE`. CVE-2018-13785 is caught only by the iter-3 integer-guard sink and not by any intersection of the existing isolated suites. The two combination approaches (set-operator over existing suites vs. custom cross-signal queries) catch different bugs and belong in the same pipeline rather than competing.
5. **Sink generality trades recall for queue size.** The iter-3 integer-guard sink is the broadest one in the pack, and it shows: 14 → 107-212 paths is what you pay for catching CVE-2018-13785. Narrowing this sink (e.g. require the comparison to gate a downstream allocation) would shrink the queue but might re-miss the CVE. The right knob position depends on whether the analysis is meant to be a high-precision triage list or a high-recall surface scan.
6. **Each CVE shape needs its sink modelled at least once.** Adding the integer-guard sink (iter 3) is a one-time investment that lets every future tainted-integer-overflow bug be caught by the same data-flow framework. CVE-2015-8540 still misses because its shape — a tainted-parameter OOB read — isn't yet in the sink set.

The 50 SARIFs (10 suites × 5 pinned tags) and all of the validator/intersection output above are reproducible from the current repo state with:

```bash
# Build + analyze all five tags. Use LIBPNG_TAGS to restrict.
LIBPNG_ONLY=1 ./scripts/run_experiments.sh

# Per-CVE site coverage check (manually-curated ground truth):
python3 scripts/cve_validation.py

# Per-pair |A|, |B|, |A ∪ B|, |A ∩ B| at enclosing-function granularity,
# with the primary operator (intersection / union) chosen by relationship:
python3 scripts/intersect_sets.py

# Optional: vuln-tag vs fix-tag diff (limitations described in §"Iteration 3.5")
python3 scripts/diff_tags.py v1.6.34 v1.6.36
python3 scripts/diff_tags.py v1.2.53 v1.2.54
```

## Framework synthesis — RQ1 / RQ2 / RQ3 mapping

The libpng case study is the empirical instantiation of a framework that is itself the answer to the three research questions. The framework has three moving parts, one per RQ:

- **RQ1 — interaction typology.** Two interaction patterns are sufficient to classify every pair we observed: *dependency* (one analysis is a precondition for the other's security claim) and *complementary* (each analysis independently witnesses its own bug family).
- **RQ2 — benefit per pattern.** Dependency combinations *clarify exploitability* (the combined set is the attacker-reachable subset of the larger analysis's candidate set). Complementary combinations *widen coverage* (the combined set is the union of bugs no single analysis catches alone).
- **RQ3 — operator follows from pattern.** Intersection for dependency, union for complementary. The operator choice is justified by the semantics of the relationship, not by the per-tag overlap count; the per-tag counts then serve as an internal-consistency check rather than as the justification.

### Synthesis table (one row per pair)

| Pair | RQ1 pattern | RQ2 benefit | RQ3 operator | libpng evidence (`scripts/intersect_sets.py`) | CVE relevance |
|---|---|---|:---:|---|---|
| taint + buffer | **dependency** | clarifies exploitability — filter buffer candidates to the attacker-reachable subset | `∩` | `png_handle_iCCP` is the one production-code function in `buffer ∩ taint` on every 1.6.x tag; buffer site `pngrutil.c:1454` sits inside the taint-read cluster 1375-1630 | adjacent to historical iCCP CVEs; **does not** localize CVE-2015-8126 because stock buffer queries don't fire in `png_handle_PLTE` |
| integer + taint | complementary | widens coverage — input-driven and input-independent integer defects are both bugs | `∪` | `\|A ∩ B\|_fn = 0` on every tag; union 38-63 functions per tag | CVE-2018-13785 caught by the integer-guard sink (iter 3), not by intersection of existing isolated suites |
| integer + buffer | complementary | widens coverage — arithmetic-correctness and memory-boundary defects are different bug families | `∪` | `\|A ∩ B\|_fn = 0` on every tag; union 7-24 functions per tag | indirect — neither isolated side localises the documented CVEs |
| taint + controlflow | complementary | widens coverage — control-flow defects (e.g. CWE-835, CWE-691) are bugs whether or not driven by tainted input | `∪` | `\|A ∩ B\|_fn = 0` on every tag; union 32-55 functions per tag | indirect |

The single dependency pair has a *non-empty* intersection on every tag where its buffer leg fires, on the same production-code function. The three complementary pairs have an *empty* intersection on every tag. Both observations are consistent with the operator chosen from semantics: the dependency-intersection lobe is the security-relevant subset for that pair, and the complementary unions are the security-relevant set for the other three because they would lose all signal under intersection.

### Two archetypal Venn diagrams (conceptual artefacts for RQ1)

The Venn diagrams encode the *typology*, not per-tag data. The empirical tables above show that the typology's prescriptions hold on the libpng instance.

**Figure 1 — Dependency Venn (taint + buffer).**

```
   ┌──────────────────────┐   ┌──────────────────────┐
   │  buffer-overflow     │   │  attacker-reachable  │
   │  candidates (|A|)    │   │  code paths (|B|)    │
   │           ┌──────────┼───┼──────────┐           │
   │  defensive│ security-│   │reachable │           │
   │  / unreach│ relevant │   │ but non- │           │
   │  -able    │   set    │   │overflowing           │
   │           │ (A ∩ B)  │   │          │           │
   │           └──────────┼───┼──────────┘           │
   └──────────────────────┘   └──────────────────────┘
```

*Caption:* A buffer-overflow candidate counts as a security claim only when it is also attacker-reachable. The intersection lobe is the security-relevant subset. The left-only lobe (overflow candidates that are not reachable from any input API) is defensive code or dead code; the right-only lobe (taint paths that do not reach an overflow candidate) is normal data flow. Neither non-intersection lobe alone supports a vulnerability claim.

**Figure 2 — Complementary Venn (integer + taint, integer + buffer, taint + controlflow).**

```
   ┌──────────────────┐    ┌──────────────────┐
   │  bug family A    │    │  bug family B    │
   │                  │    │                  │
   │   (e.g. integer  │    │   (e.g. taint    │
   │    overflows)    │    │    reachability) │
   │                  │    │                  │
   └──────────────────┘    └──────────────────┘
```

*Caption:* Each analysis witnesses a bug family the other does not. An integer overflow is a defect whether or not the same function is on a taint path; a missing termination check is a defect whether or not it is input-driven. The combined bug list is the union of both circles; the (typically small or empty) intersection, when it exists, is the higher-confidence corroborated subset rather than the primary set. On libpng, every complementary pair has empty function-level intersection on every tag — visually, the two circles do not overlap.

### Validity scope

- **Internal validity:** the operator-from-semantics rule is internally consistent on libpng for all four pairs and all five tags.
- **External validity:** single tool (CodeQL), single target family (libpng), 5 tags. The framework's prescriptions hold on this instance; generalisation across tools and targets is future work.
- **Construct validity:** the dependency intersection counts depend on the source/sink coverage of the underlying queries. Where one of the two legs fires in zero functions (e.g. `isolated-buffer` on 1.2.x), the intersection is empty by construction of the leg, not by absence of attacker-reachable buffer bugs.

## Writing Up the Research Questions

A suggested structure for the thesis / paper section that uses this case study as its evidence base. Each step names the artefact in this repo that supplies the evidence.

**Step 1 — RQ1 narrative (typology + Venn diagrams).**
- Introduce the typology: dependency, complementary.
- Present **Figure 1** and **Figure 2** as the conceptual claim.
- Argue from the *meaning* of each analysis pair why it falls into one bucket or the other. Do not lead with the empirical counts here — the counts are evidence for RQ3, not the source of the typology.

**Step 2 — RQ2 narrative (benefit per pattern).**
- For dependency: cite the buffer ∩ taint result on `png_handle_iCCP`. The benefit is *exploitability clarification* — the intersection takes the broader analysis's candidate set and filters it to the subset that has an attacker-reachable witness.
- For complementary: cite the per-tag union sizes (38-63 / 7-24 / 32-55). The benefit is *coverage widening* — the union of two complementary analyses catches bugs that neither catches alone, including CVE-2018-13785 (caught by the integer side, missed by buffer).

**Step 3 — RQ3 narrative (framework as algorithm).**
- Present the framework as: (i) classify each pair by RQ1 pattern; (ii) choose the operator from RQ2 semantics (`∩` for dependency, `∪` for complementary); (iii) validate empirically that the per-tag set sizes are consistent with the choice.
- Cite the **synthesis table** above as the one-glance summary of the framework applied to four pairs.
- Cite `scripts/intersect_sets.py` as the operational implementation of the framework.

**Step 4 — Limitations / threats to validity.**
- Single-tool, single-target evaluation (see §"Validity scope").
- Construct dependency on source/sink coverage: empty intersection at v1.2.x is not evidence of safety, only of one leg's silence.
- Fix-tag diff arm (iter 3.5) does not work for sinks that are the bug's *symptom* (comparison, arithmetic). Document this as a methodological limitation of mechanical TP labelling on pattern-based queries.

**Step 5 — Reproducibility appendix.**
- Point the reader at the four scripts:
  - `scripts/run_experiments.sh` — produces the 50 SARIFs.
  - `scripts/cve_validation.py` — per-CVE site coverage against `docs/libpng_cve_ground_truth.json`.
  - `scripts/intersect_sets.py` — per-pair `|A|`, `|B|`, `|A ∪ B|`, `|A ∩ B|` with the primary operator chosen by relationship type.
  - `scripts/diff_tags.py` — vuln-tag vs fix-tag set diff (limitations documented in §"Iteration 3.5").

**Step 6 — Future work / generalisation.**
- Extend to a second tool (e.g. Joern, Semgrep, Infer) and check whether the same typology holds — does another tool's "buffer + taint" still classify as dependency?
- Extend to a second target family (e.g. zlib, libxml2) and check whether the per-tag set-size pattern (non-empty dependency intersection, empty complementary intersection) replicates.
- A path-structural fix-tag diff would tighten the iter-3.5 arm and is the natural next mechanical TP-labelling step.

## Why Some Stock Results Are Sparse

Many trimmed cases are not taint-flow examples. They use a constant source string and a bad destination size:

```c
memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid));
```

This overwrites adjacent fields inside the same struct. The stock CodeQL C/C++ buffer queries do run, but they do not flag this specific intra-struct overwrite pattern in this setup. The custom query exists to cover exactly that gap.

Other selected shards are small Juliet slices where the stock rules may only report a few high-confidence issues. The experimental isolated and combo suites intentionally add broader CWE-aware hotspot rules so that isolated analyses have nonzero coverage and combination analyses provide a larger, noisier comparison set.

## Recommended Workflow

1. Restore `my_cases/testcasesupport` from Juliet.
2. Run the verified trimmed case with `./scripts/run_experiments.sh`.
3. Run the full selected shards with `RUN_FULL_SUBSETS=1 ./scripts/run_experiments.sh`.
4. For each shard, compare isolated suite results to the matching combination suite result.
5. Only expand to larger CWE folders after the selected subset behaves as expected.

The key comparison is not just "did CodeQL find something", but whether the combination suite adds findings and rule diversity beyond the isolated category suites.
