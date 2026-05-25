#!/usr/bin/env bash
set -euo pipefail

CODEQL="${CODEQL:-./codeql/codeql}"
DB_ROOT="${DB_ROOT:-codeql-dbs}"
RESULT_ROOT="${RESULT_ROOT:-results}"
RUN_FULL_SUBSETS="${RUN_FULL_SUBSETS:-0}"
RUN_LIBPNG="${RUN_LIBPNG:-1}"
LIBPNG_ONLY="${LIBPNG_ONLY:-0}"

TARGETS_ROOT="${TARGETS_ROOT:-targets}"
LIBPNG_REPO="${LIBPNG_REPO:-https://github.com/pnggroup/libpng.git}"
# Space-separated list of libpng tags. Defaults: one clean baseline plus two
# vuln/fix pairs.
#   v1.6.37  clean modern baseline
#   v1.6.34  pre-fix for CVE-2018-13785 (integer overflow in png_check_chunk_length)
#   v1.6.36  fix tag for CVE-2018-13785
#   v1.2.53  legacy 1.2.x, pre-fix for CVE-2015-8126 and CVE-2015-8540
#   v1.2.54  fix tag for CVE-2015-8126 (CVE-2015-8540 was fixed in 1.2.55)
# Override with LIBPNG_TAGS="vX.Y.Z ...".
LIBPNG_TAGS="${LIBPNG_TAGS:-v1.6.37 v1.6.34 v1.6.36 v1.2.53 v1.2.54}"

STOCK_SUITE="${STOCK_SUITE:-codeql/qlpacks/codeql/cpp-queries/1.6.2/codeql-suites/cpp-security-and-quality.qls}"
CUSTOM_SUITE="${CUSTOM_SUITE:-queries/combined-cpp/codeql-suites/custom-combinations.qls}"
SUITE_ROOT="${SUITE_ROOT:-queries/combined-cpp/codeql-suites/experiment}"

TAINT_SUITE="${TAINT_SUITE:-$SUITE_ROOT/isolated-taint.qls}"
BUFFER_SUITE="${BUFFER_SUITE:-$SUITE_ROOT/isolated-buffer.qls}"
INTEGER_SUITE="${INTEGER_SUITE:-$SUITE_ROOT/isolated-integer.qls}"
CONTROLFLOW_SUITE="${CONTROLFLOW_SUITE:-$SUITE_ROOT/isolated-controlflow.qls}"

BUFFER_INTEGER_SUITE="${BUFFER_INTEGER_SUITE:-$SUITE_ROOT/combo-buffer-integer.qls}"
INTEGER_TAINT_SUITE="${INTEGER_TAINT_SUITE:-$SUITE_ROOT/combo-integer-taint.qls}"
TAINT_BUFFER_SUITE="${TAINT_BUFFER_SUITE:-$SUITE_ROOT/combo-taint-buffer.qls}"
TAINT_BUFFER_FLOW_SUITE="${TAINT_BUFFER_FLOW_SUITE:-$SUITE_ROOT/combo-taint-buffer-flow.qls}"
TAINT_CONTROLFLOW_SUITE="${TAINT_CONTROLFLOW_SUITE:-$SUITE_ROOT/combo-taint-controlflow.qls}"

mkdir -p "$DB_ROOT" "$RESULT_ROOT"

require_codeql() {
  if [ ! -x "$CODEQL" ]; then
    echo "CodeQL CLI not found at '$CODEQL'. Set CODEQL=/path/to/codeql or unpack the bundle into ./codeql." >&2
    exit 2
  fi
}

create_db() {
  local name="$1"
  local source_root="$2"
  local build_command="$3"
  local db="$DB_ROOT/$name"

  echo
  echo "== Creating database: $name"
  rm -rf "$db"
  "$CODEQL" database create "$db" \
    --language=cpp \
    --source-root="$source_root" \
    --command="$build_command"
}

analyze() {
  local name="$1"
  local query_label="$2"
  shift 2
  local db="$DB_ROOT/$name"
  local output="$RESULT_ROOT/$name.$query_label.sarif"

  echo
  echo "== Analyzing: $name [$query_label]"
  "$CODEQL" database analyze "$db" "$@" \
    --format=sarifv2.1.0 \
    --output="$output" \
    --rerun

  python3 scripts/summarize_sarif.py "$output"
}

run_trimmed_taint_buffer() {
  local name="taint-buffer-trimmed"
  create_db "$name" "my_cases/taint+buffer_trimmed" "sh build.sh"

  analyze "$name" "stock" "$STOCK_SUITE"
  analyze "$name" "isolated-taint" "$TAINT_SUITE"
  analyze "$name" "isolated-buffer" "$BUFFER_SUITE"
  analyze "$name" "combo-taint-buffer" "$TAINT_BUFFER_SUITE"
  analyze "$name" "combo-taint-buffer-flow" "$TAINT_BUFFER_FLOW_SUITE"
  analyze "$name" "custom-only" "$CUSTOM_SUITE"
}

# Shard where user input actually flows into a buffer write/index. The
# *_overrun_memcpy_* shards use sizeof(struct), a constant, and are not
# attacker-controllable, so the chained taint-to-buffer query has nothing
# to find there. Each file here contains:
#   bad()       fgets -> atoi -> buffer[data]                 (TP-expected)
#   goodG2B()   hardcoded data = 7, no fgets                  (TN-expected)
#   goodB2G()   fgets -> atoi -> bounds-check -> buffer[data] (TN, sanitised)
run_taint_to_buffer_flow_cwe129_fgets() {
  local case_dir="my_cases/taint + buffer/CWE121_Stack_Based_Buffer_Overflow/s01"

  if ! can_build_makefile_case "$case_dir"; then
    echo
    echo "== Skipping: taint-buffer-cwe129-fgets-s01"
    echo "Missing Juliet support files (testcasesupport/io.c and std_thread.c)."
    return 0
  fi

  local name="taint-buffer-cwe129-fgets-s01"
  local build_script
  build_script="$(pwd)/scripts/build_selected_c_cases.sh"

  local files=()
  local i
  for i in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18; do
    files+=("CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_${i}.c")
  done

  create_db "$name" "$case_dir" "$build_script ${files[*]}"
  analyze "$name" "stock" "$STOCK_SUITE"
  analyze "$name" "isolated-buffer" "$BUFFER_SUITE"
  analyze "$name" "combo-taint-buffer" "$TAINT_BUFFER_SUITE"
  analyze "$name" "combo-taint-buffer-flow" "$TAINT_BUFFER_FLOW_SUITE"
}

support_dir_for() {
  local case_dir="$1"
  (cd "$case_dir" && realpath "../../../testcasesupport")
}

can_build_makefile_case() {
  local case_dir="$1"
  local support_dir
  support_dir="$(support_dir_for "$case_dir")"
  [ -f "$case_dir/Makefile" ] && [ -f "$support_dir/io.c" ] && [ -f "$support_dir/std_thread.c" ]
}

run_makefile_case_if_available() {
  local name="$1"
  local case_dir="$2"
  local suite_a="$3"
  local label_a="$4"
  local suite_b="$5"
  local label_b="$6"
  local combo_suite="$7"
  local combo_label="$8"

  if ! can_build_makefile_case "$case_dir"; then
    echo
    echo "== Skipping: $name"
    echo "Missing Juliet support files for '$case_dir'. Expected ../../../testcasesupport/io.c and std_thread.c."
    return 0
  fi

  create_db "$name" "$case_dir" "make clean all"
  analyze "$name" "stock" "$STOCK_SUITE"
  analyze "$name" "$label_a" "$suite_a"
  analyze "$name" "$label_b" "$suite_b"
  analyze "$name" "$combo_label" "$combo_suite"
}

run_selected_files_case_if_available() {
  local name="$1"
  local case_dir="$2"
  local suite_a="$3"
  local label_a="$4"
  local suite_b="$5"
  local label_b="$6"
  local combo_suite="$7"
  local combo_label="$8"
  shift 8

  if ! can_build_makefile_case "$case_dir"; then
    echo
    echo "== Skipping: $name"
    echo "Missing Juliet support files for '$case_dir'. Expected ../../../testcasesupport/io.c and std_thread.c."
    return 0
  fi

  local build_script
  build_script="$(pwd)/scripts/build_selected_c_cases.sh"

  create_db "$name" "$case_dir" "$build_script $*"
  analyze "$name" "stock" "$STOCK_SUITE"
  analyze "$name" "$label_a" "$suite_a"
  analyze "$name" "$label_b" "$suite_b"
  analyze "$name" "$combo_label" "$combo_suite"
}

ensure_libpng() {
  local tag="$1"
  local dir="$TARGETS_ROOT/libpng-$tag"
  if [ ! -d "$dir/.git" ]; then
    mkdir -p "$TARGETS_ROOT"
    git clone --depth 1 --branch "$tag" "$LIBPNG_REPO" "$dir"
  fi
  printf '%s' "$dir"
}

have_zlib() {
  ldconfig -p 2>/dev/null | grep -q 'libz\.so' && return 0
  [ -f /usr/include/zlib.h ] || [ -f /usr/local/include/zlib.h ]
}

# Run the full isolated + combination matrix on one pinned libpng tag.
run_libpng_target() {
  local tag="$1"
  local src name
  src="$(ensure_libpng "$tag")"
  name="libpng-$tag"

  local build_script
  build_script="$(pwd)/scripts/build_libpng.sh"
  create_db "$name" "$src" "bash $build_script"

  # Baseline.
  analyze "$name" "stock" "$STOCK_SUITE"

  # Isolated suites, one per analysis category.
  analyze "$name" "isolated-taint"       "$TAINT_SUITE"
  analyze "$name" "isolated-buffer"      "$BUFFER_SUITE"
  analyze "$name" "isolated-integer"     "$INTEGER_SUITE"
  analyze "$name" "isolated-controlflow" "$CONTROLFLOW_SUITE"

  # Pairwise combinations.
  analyze "$name" "combo-taint-buffer"       "$TAINT_BUFFER_SUITE"
  analyze "$name" "combo-taint-buffer-flow"  "$TAINT_BUFFER_FLOW_SUITE"
  analyze "$name" "combo-taint-controlflow"  "$TAINT_CONTROLFLOW_SUITE"
  analyze "$name" "combo-integer-taint"      "$INTEGER_TAINT_SUITE"
  analyze "$name" "combo-buffer-integer"     "$BUFFER_INTEGER_SUITE"
}

run_libpng_all() {
  if [ "$RUN_LIBPNG" != "1" ]; then
    echo
    echo "== Skipping libpng (RUN_LIBPNG=0)"
    return 0
  fi

  if ! have_zlib; then
    echo
    echo "== Skipping libpng: zlib headers/library not found (apt install zlib1g-dev)"
    return 0
  fi

  local tag
  for tag in $LIBPNG_TAGS; do
    run_libpng_target "$tag"
  done
}

run_selected_full_subsets() {
  run_selected_files_case_if_available \
    "buffer-integer-cwe190-s02" \
    "my_cases/buffer + integer/CWE190_Integer_Overflow/s02" \
    "$BUFFER_SUITE" "isolated-buffer" \
    "$INTEGER_SUITE" "isolated-integer" \
    "$BUFFER_INTEGER_SUITE" "combo-buffer-integer" \
    CWE190_Integer_Overflow__int_connect_socket_add_01.c \
    CWE190_Integer_Overflow__int_connect_socket_add_02.c \
    CWE190_Integer_Overflow__int_connect_socket_add_03.c \
    CWE190_Integer_Overflow__int_connect_socket_add_04.c \
    CWE190_Integer_Overflow__int_connect_socket_add_05.c \
    CWE190_Integer_Overflow__int_connect_socket_add_06.c \
    CWE190_Integer_Overflow__int_connect_socket_add_07.c \
    CWE190_Integer_Overflow__int_connect_socket_add_08.c \
    CWE190_Integer_Overflow__int_connect_socket_add_09.c \
    CWE190_Integer_Overflow__int_connect_socket_add_10.c \
    CWE190_Integer_Overflow__int_connect_socket_add_11.c \
    CWE190_Integer_Overflow__int_connect_socket_add_12.c \
    CWE190_Integer_Overflow__int_connect_socket_add_13.c \
    CWE190_Integer_Overflow__int_connect_socket_add_14.c \
    CWE190_Integer_Overflow__int_connect_socket_add_15.c \
    CWE190_Integer_Overflow__int_connect_socket_add_16.c \
    CWE190_Integer_Overflow__int_connect_socket_add_17.c \
    CWE190_Integer_Overflow__int_connect_socket_add_18.c

  run_selected_files_case_if_available \
    "integer-taint-cwe190-s03" \
    "my_cases/integer + taint/CWE190_Integer_Overflow/s03" \
    "$INTEGER_SUITE" "isolated-integer" \
    "$TAINT_SUITE" "isolated-taint" \
    "$INTEGER_TAINT_SUITE" "combo-integer-taint" \
    CWE190_Integer_Overflow__int_fgets_multiply_01.c \
    CWE190_Integer_Overflow__int_fgets_multiply_02.c \
    CWE190_Integer_Overflow__int_fgets_multiply_03.c \
    CWE190_Integer_Overflow__int_fgets_multiply_04.c \
    CWE190_Integer_Overflow__int_fgets_multiply_05.c \
    CWE190_Integer_Overflow__int_fgets_multiply_06.c \
    CWE190_Integer_Overflow__int_fgets_multiply_07.c \
    CWE190_Integer_Overflow__int_fgets_multiply_08.c \
    CWE190_Integer_Overflow__int_fgets_multiply_09.c \
    CWE190_Integer_Overflow__int_fgets_multiply_10.c \
    CWE190_Integer_Overflow__int_fgets_multiply_11.c \
    CWE190_Integer_Overflow__int_fgets_multiply_12.c \
    CWE190_Integer_Overflow__int_fgets_multiply_13.c \
    CWE190_Integer_Overflow__int_fgets_multiply_14.c \
    CWE190_Integer_Overflow__int_fgets_multiply_15.c \
    CWE190_Integer_Overflow__int_fgets_multiply_16.c \
    CWE190_Integer_Overflow__int_fgets_multiply_17.c \
    CWE190_Integer_Overflow__int_fgets_multiply_18.c

  run_selected_files_case_if_available \
    "integer-taint-cwe191-s03" \
    "my_cases/integer + taint/CWE191_Integer_Underflow/s03" \
    "$INTEGER_SUITE" "isolated-integer" \
    "$TAINT_SUITE" "isolated-taint" \
    "$INTEGER_TAINT_SUITE" "combo-integer-taint" \
    CWE191_Integer_Underflow__int_rand_multiply_01.c \
    CWE191_Integer_Underflow__int_rand_multiply_02.c \
    CWE191_Integer_Underflow__int_rand_multiply_03.c \
    CWE191_Integer_Underflow__int_rand_multiply_04.c \
    CWE191_Integer_Underflow__int_rand_multiply_05.c \
    CWE191_Integer_Underflow__int_rand_multiply_06.c \
    CWE191_Integer_Underflow__int_rand_multiply_07.c \
    CWE191_Integer_Underflow__int_rand_multiply_08.c \
    CWE191_Integer_Underflow__int_rand_multiply_09.c \
    CWE191_Integer_Underflow__int_rand_multiply_10.c \
    CWE191_Integer_Underflow__int_rand_multiply_11.c \
    CWE191_Integer_Underflow__int_rand_multiply_12.c \
    CWE191_Integer_Underflow__int_rand_multiply_13.c \
    CWE191_Integer_Underflow__int_rand_multiply_14.c \
    CWE191_Integer_Underflow__int_rand_multiply_15.c \
    CWE191_Integer_Underflow__int_rand_multiply_16.c \
    CWE191_Integer_Underflow__int_rand_multiply_17.c \
    CWE191_Integer_Underflow__int_rand_multiply_18.c

  run_selected_files_case_if_available \
    "taint-buffer-cwe121-s01" \
    "my_cases/taint + buffer/CWE121_Stack_Based_Buffer_Overflow/s01" \
    "$TAINT_SUITE" "isolated-taint" \
    "$BUFFER_SUITE" "isolated-buffer" \
    "$TAINT_BUFFER_SUITE" "combo-taint-buffer" \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_02.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_03.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_04.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_05.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_06.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_07.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_08.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_09.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_10.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_11.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_12.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_13.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_14.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_15.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_16.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_17.c \
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_18.c

  run_selected_files_case_if_available \
    "taint-buffer-cwe122-s01" \
    "my_cases/taint + buffer/CWE122_Heap_Based_Buffer_Overflow/s01" \
    "$TAINT_SUITE" "isolated-taint" \
    "$BUFFER_SUITE" "isolated-buffer" \
    "$TAINT_BUFFER_SUITE" "combo-taint-buffer" \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_02.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_03.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_04.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_05.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_06.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_07.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_08.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_09.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_10.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_11.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_12.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_13.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_14.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_15.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_16.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_17.c \
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_18.c

  run_selected_files_case_if_available \
    "taint-controlflow-cwe134-s01" \
    "my_cases/taint + control flow/CWE134_Uncontrolled_Format_String/s01" \
    "$TAINT_SUITE" "isolated-taint" \
    "$CONTROLFLOW_SUITE" "isolated-controlflow" \
    "$TAINT_CONTROLFLOW_SUITE" "combo-taint-controlflow" \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_01.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_02.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_03.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_04.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_05.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_06.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_07.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_08.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_09.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_10.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_11.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_12.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_13.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_14.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_15.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_16.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_17.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_18.c
}

main() {
  require_codeql

  # LIBPNG_ONLY=1 skips Juliet entirely and runs only the libpng matrix.
  if [ "$LIBPNG_ONLY" = "1" ]; then
    run_libpng_all
    return 0
  fi

  run_trimmed_taint_buffer

  # Taint-to-buffer flow demo. Skips itself if Juliet testcasesupport files
  # are missing, so it is safe to run by default.
  run_taint_to_buffer_flow_cwe129_fgets

  # libpng matrix. Runs all isolated and combination suites on every tag in
  # $LIBPNG_TAGS. Skips itself if zlib is unavailable.
  run_libpng_all

  if [ "$RUN_FULL_SUBSETS" = "1" ]; then
    run_selected_full_subsets
  else
    echo
    echo "Full Juliet shards skipped. Set RUN_FULL_SUBSETS=1 after restoring testcasesupport."
  fi
}

main "$@"
