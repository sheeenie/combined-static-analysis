#!/usr/bin/env bash
set -euo pipefail

CODEQL="${CODEQL:-./codeql/codeql}"
DB_ROOT="${DB_ROOT:-codeql-dbs}"
RESULT_ROOT="${RESULT_ROOT:-results}"
RUN_FULL_SUBSETS="${RUN_FULL_SUBSETS:-0}"

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
  analyze "$name" "custom-only" "$CUSTOM_SUITE"
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

run_selected_full_subsets() {
  run_selected_files_case_if_available \
    "buffer-integer-cwe190-s02" \
    "my_cases/buffer + integer/CWE190_Integer_Overflow/s02" \
    "$BUFFER_SUITE" "isolated-buffer" \
    "$INTEGER_SUITE" "isolated-integer" \
    "$BUFFER_INTEGER_SUITE" "combo-buffer-integer" \
    CWE190_Integer_Overflow__int_connect_socket_add_01.c \
    CWE190_Integer_Overflow__int_connect_socket_add_02.c \
    CWE190_Integer_Overflow__int_connect_socket_add_03.c

  run_selected_files_case_if_available \
    "integer-taint-cwe190-s03" \
    "my_cases/integer + taint/CWE190_Integer_Overflow/s03" \
    "$INTEGER_SUITE" "isolated-integer" \
    "$TAINT_SUITE" "isolated-taint" \
    "$INTEGER_TAINT_SUITE" "combo-integer-taint" \
    CWE190_Integer_Overflow__int_fgets_multiply_01.c \
    CWE190_Integer_Overflow__int_fgets_multiply_02.c \
    CWE190_Integer_Overflow__int_fgets_multiply_03.c

  run_selected_files_case_if_available \
    "integer-taint-cwe191-s03" \
    "my_cases/integer + taint/CWE191_Integer_Underflow/s03" \
    "$INTEGER_SUITE" "isolated-integer" \
    "$TAINT_SUITE" "isolated-taint" \
    "$INTEGER_TAINT_SUITE" "combo-integer-taint" \
    CWE191_Integer_Underflow__int_rand_multiply_01.c \
    CWE191_Integer_Underflow__int_rand_multiply_02.c \
    CWE191_Integer_Underflow__int_rand_multiply_03.c

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
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_05.c

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
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_05.c

  run_selected_files_case_if_available \
    "taint-controlflow-cwe134-s01" \
    "my_cases/taint + control flow/CWE134_Uncontrolled_Format_String/s01" \
    "$TAINT_SUITE" "isolated-taint" \
    "$CONTROLFLOW_SUITE" "isolated-controlflow" \
    "$TAINT_CONTROLFLOW_SUITE" "combo-taint-controlflow" \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_01.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_02.c \
    CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_03.c
}

main() {
  require_codeql
  run_trimmed_taint_buffer

  if [ "$RUN_FULL_SUBSETS" = "1" ]; then
    run_selected_full_subsets
  else
    echo
    echo "Full selected Juliet shards were not run. Set RUN_FULL_SUBSETS=1 after restoring testcasesupport."
  fi
}

main "$@"
