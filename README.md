# Combined Static Analysis Experiments

This repository is set up to compare stock CodeQL C/C++ analysis against custom combination-oriented queries on selected Juliet-style CWE subsets.

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

Current custom query:

```text
queries/combined-cpp/StructFieldMemcpyOverrun.ql
```

It reports `memcpy` or `memmove` calls where the destination is a struct field and the copy size is larger than that field can hold. This catches the trimmed Juliet pattern:

```c
memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid));
```

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

Compile-check the custom query:

```bash
./codeql/codeql query compile \
  --search-path=codeql/qlpacks \
  queries/combined-cpp/StructFieldMemcpyOverrun.ql
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
| `.isolated-taint.sarif` | taint-sensitive baseline suite only |
| `.isolated-buffer.sarif` | buffer/memory-bound baseline suite only |
| `.combo-taint-buffer.sarif` | taint + buffer suite, including the custom struct-field overwrite query |
| `.custom-only.sarif` | custom query suite only |

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

## Current Verified Result

On `taint+buffer_trimmed`:

| Analysis | Expected result |
|---|---|
| stock CodeQL security-and-quality | `0` alerts |
| isolated taint suite | `0` alerts |
| isolated buffer suite | `0` alerts |
| custom query suite | `10` alerts |
| taint + buffer combination suite | `10` alerts |

The 10 custom alerts correspond to:

```text
5 CWE121 stack-based buffer-overflow memcpy cases
5 CWE122 heap-based buffer-overflow memcpy cases
```

Each finding reports the bad sink where 32 bytes are copied into the `charFirst` field, which has size 16 bytes.

On the selected Juliet shards with `RUN_FULL_SUBSETS=1`:

| Shard | Stock | Isolated A | Isolated B | Combination |
|---|---:|---:|---:|---:|
| `buffer-integer-cwe190-s02` | 0 | buffer: 0 | integer: 0 | 0 |
| `integer-taint-cwe190-s03` | 5 constant-comparison alerts | integer: 0 | taint: 6 | 6 |
| `integer-taint-cwe191-s03` | 5 constant-comparison alerts | integer: 0 | taint: 0 | 0 |
| `taint-buffer-cwe121-s01` | 0 | taint: 0 | buffer: 0 | 5 |
| `taint-buffer-cwe122-s01` | 0 | taint: 0 | buffer: 0 | 5 |
| `taint-controlflow-cwe134-s01` | 3 | taint: 3 | control flow: 0 | 3 |

## Why Stock CodeQL Reports 0 Here

The trimmed cases are not taint-flow examples. They use a constant source string and a bad destination size:

```c
memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid));
```

This overwrites adjacent fields inside the same struct. The stock CodeQL C/C++ buffer queries do run, but they do not flag this specific intra-struct overwrite pattern in this setup. The custom query exists to cover exactly that gap.

## Recommended Workflow

1. Restore `my_cases/testcasesupport` from Juliet.
2. Run the verified trimmed case with `./scripts/run_experiments.sh`.
3. Run the full selected shards with `RUN_FULL_SUBSETS=1 ./scripts/run_experiments.sh`.
4. For each shard, compare isolated suite results to the matching combination suite result.
5. Only expand to larger CWE folders after the selected subset behaves as expected.

The key comparison is not just "did CodeQL find something", but whether the combination query adds findings that isolated stock queries miss.
