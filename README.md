# Combined Static Analysis

This repository contains the code and experiments for our bachelor thesis on combining static analysis categories (taint, buffer, integer, control flow) in CodeQL. It runs the stock CodeQL C/C++ suite, four isolated category suites, and several pairwise combination suites against selected Juliet shards and a few libpng release tags, including two vuln/fix pairs for CVE-2018-13785 and CVE-2015-8126.

The thesis splits analysis pairs into *dependency* and *complementary* combinations and assigns an operator to each (intersection for dependency, union for complementary). We test the framework on libpng.

This README only covers how to set up and run the experiments. The methodology, results and conclusions are in our thesis: *An Empirical Study of Coupled Static Security Analyses for Vulnerability Assessment*.

## Authors

- William Johansson
- Sin Yee Sheenie Chan
- Ling Svahn

## Requirements

- Linux or WSL (the scripts were developed on WSL2 / Ubuntu).
- A C toolchain (`build-essential`) and `make`.
- `git`, `python3`, `bash`.
- `zlib` headers and library for the libpng builds:
  ```bash
  sudo apt install build-essential zlib1g-dev git python3
  ```
- The CodeQL CLI bundle (see below).

## Setup

### 1. Clone the repository

```bash
git clone <repo-url> combined-static-analysis
cd combined-static-analysis
```

### 2. Install CodeQL

Download the CodeQL CLI bundle from the [CodeQL releases page](https://github.com/github/codeql-action/releases) and unpack it into the repo root so the CLI lives at `./codeql/codeql`:

```bash
./codeql/codeql version
```

You can also use an existing install by exporting `CODEQL`:

```bash
export CODEQL=/path/to/codeql
```

The `codeql/` directory and any downloaded archives are local artefacts and should not be committed.

### 3. (Optional) Restore Juliet support files

The Juliet-style shards in `my_cases/<combination>/` need the Juliet test-case support headers and sources at:

```
my_cases/testcasesupport/io.c
my_cases/testcasesupport/std_thread.c
my_cases/testcasesupport/*.h
```

These are not redistributed here. Drop them in from the upstream Juliet C/C++ test suite if you want to run the full subset experiments. The default verified run (`taint+buffer_trimmed`) does **not** need them.

### 4. (Optional) libpng targets

`scripts/run_experiments.sh` clones libpng release tags into `targets/libpng-<tag>/` on demand. No manual download is needed, just make sure `zlib1g-dev` is installed.

## Running the experiments

### Default verified run

Runs the self-contained `taint+buffer_trimmed` Juliet subset plus the libpng matrix:

```bash
./scripts/run_experiments.sh
```

SARIFs are written under `results/`. Summarize any SARIF file with:

```bash
python3 scripts/summarize_sarif.py results/<file>.sarif
```

### Full Juliet subset (requires `my_cases/testcasesupport`)

```bash
RUN_FULL_SUBSETS=1 ./scripts/run_experiments.sh
```

### libpng only

```bash
LIBPNG_ONLY=1 ./scripts/run_experiments.sh
```

Pin specific libpng tags (defaults to `v1.6.37 v1.6.34 v1.2.53`):

```bash
LIBPNG_TAGS="v1.6.37 v1.6.34 v1.6.36 v1.2.53 v1.2.54" LIBPNG_ONLY=1 ./scripts/run_experiments.sh
```

Other env knobs: `CODEQL`, `LIBPNG_REPO`, `TARGETS_ROOT`, `RUN_LIBPNG=0`.

### Validation and analysis

```bash
# Per-CVE site coverage (uses docs/libpng_cve_ground_truth.json):
python3 scripts/cve_validation.py
python3 scripts/cve_validation.py v1.6.34            # restrict to one tag

# Set-operator analysis per pair (|A|, |B|, |A ∪ B|, |A ∩ B|):
python3 scripts/intersect_sets.py
python3 scripts/intersect_sets.py v1.6.34

# Vuln-tag vs fix-tag diff:
python3 scripts/diff_tags.py v1.6.34 v1.6.36
python3 scripts/diff_tags.py v1.2.53 v1.2.54
```

### Compile-check the custom queries

```bash
./codeql/codeql query compile --search-path=codeql/qlpacks queries/combined-cpp/*.ql
```

## Repository layout

```
queries/combined-cpp/   Custom CodeQL queries (.ql) and suites (.qls)
my_cases/               Selected Juliet-style CWE shards used as benchmarks
targets/                libpng release-tag working copies (created on demand)
scripts/                Run + analysis scripts (bash and python)
results/                Generated SARIF output
codeql-dbs/             Generated CodeQL databases
docs/                   Ground-truth data and research notes
```

## License

MIT. See [`licence.md`](licence.md).

## Acknowledgements

The benchmark shards under `my_cases/` come from NIST's Juliet Test Suite for C/C++. The real-world target is [libpng](https://github.com/pnggroup/libpng), analysed at unmodified upstream release tags.
