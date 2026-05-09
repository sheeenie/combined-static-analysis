#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <case-file.c|case-file.cpp>..." >&2
  exit 2
fi

support_dir=""
for candidate in ../../../testcasesupport ../../testcasesupport ../testcasesupport testcasesupport; do
  if [ -f "$candidate/std_testcase.h" ]; then
    support_dir="$candidate"
    break
  fi
done

if [ -z "$support_dir" ]; then
  echo "Could not find Juliet testcasesupport from $(pwd)." >&2
  exit 2
fi

rm -f -- *.o *.out

for src in "$@"; do
  if [ ! -f "$src" ]; then
    echo "Missing selected source file: $src" >&2
    exit 2
  fi

  obj="${src%.*}.o"
  case "$src" in
    *.cpp|*.cc|*.cxx) compiler="${CXX:-g++}" ;;
    *) compiler="${CC:-gcc}" ;;
  esac

  "$compiler" -c -I "$support_dir" "$src" -o "$obj"
done
