# Combined Static Analysis Experiments

This repository is set up to compare stock CodeQL C/C++ analysis against broader experimental isolated suites and custom combination-oriented queries on selected Juliet-style CWE subsets.

The verified paths are the self-contained `taint+buffer_trimmed` subset plus the selected Juliet shards under `my_cases/<combination>/.../sXX`. Juliet support files are expected at `my_cases/testcasesupport`; the run script compiles a small explicit file subset from each shard so the experiment stays fast and reproducible.

## What Is Being Tested

The high-level combinations are:

| Combination | Repo path | Selected CWE subset |
|---|---|---|
| buffer + integer | `my_cases/buffer + integer` | `CWE190_Integer_Overflow/s02` |
| integer + taint | `my_cases/integer + taint` | `CWE190_Integer_Overflow/s03`, `CWE191_Integer_Underflow/s03` |
| taint + buffer | `my_cases/taint+buffer_trimmed` and `my_cases/taint + buffer` | verified trimmed `CWE121`, `CWE122`; selected full `CWE121/s01`, `CWE122/s01` |
| taint + control flow | `my_cases/taint + control flow` | `CWE134_Uncontrolled_Format_String/s01`; `CWE606` is relevant but larger and not enabled by default |

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
```

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

On `taint+buffer_trimmed`:

| Analysis | Expected result |
|---|---|
| stock CodeQL security-and-quality | `0` alerts |
| isolated taint suite | `0` alerts |
| isolated buffer suite | `28` alerts |
| custom query suite | `10` alerts |
| taint + buffer combination suite | `38` alerts |

The 10 precise custom alerts correspond to:

```text
5 CWE121 stack-based buffer-overflow memcpy cases
5 CWE122 heap-based buffer-overflow memcpy cases
```

Each finding reports the bad sink where 32 bytes are copied into the `charFirst` field, which has size 16 bytes.

The broader isolated buffer suite also reports all relevant `memcpy` hotspots in the trimmed shard, including good-path and bad-path copies. This is intentional: the isolated suite is a coverage baseline, while the precise custom query marks the more specific overrun pattern.

Recent validation runs on selected Juliet shards:

| Shard | Isolated A | Isolated B | Combination |
|---|---:|---:|---:|
| `buffer-integer-cwe190-s02` | buffer: `16` | integer: `37` | `69` |
| `integer-taint-cwe190-s03` | integer: `34` | taint: `30` | `85` |
| `taint-buffer-trimmed` | taint: `0` | buffer: `28` | `38` |
| `taint-controlflow-cwe134-s01` | taint: `11` | control flow: `76` | `155` |

These counts were produced from existing databases after expanding the suites. Rerun `./scripts/run_experiments.sh` or `RUN_FULL_SUBSETS=1 ./scripts/run_experiments.sh` to regenerate normal, non-`.updated` SARIF outputs in `results/`.

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
