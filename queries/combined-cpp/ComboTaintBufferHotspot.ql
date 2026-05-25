/**
 * @name Buffer operation in function with external input
 * @description Flags copy/write calls in functions that also read external input. Broad combination rule, complements the precise buffer-overrun checks.
 * @kind problem
 * @id cpp/experimental/combo-taint-buffer-hotspot
 * @problem.severity warning
 * @security-severity 7.2
 * @precision low
 * @tags security
 *       external/cwe/cwe-20
 *       external/cwe/cwe-119
 *       external/cwe/cwe-120
 *       external/cwe/cwe-121
 *       external/cwe/cwe-122
 *       external/cwe/cwe-787
 *       external/cwe/cwe-805
 */

import cpp
import LibpngSources

predicate inputApi(FunctionCall call) {
  call.getTarget().hasGlobalName([
    "recv", "recvfrom", "read", "fread", "fgets", "gets", "scanf", "fscanf", "sscanf",
    "getchar", "getenv", "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll",
    "strtoull"
  ])
  or
  libpngInputApi(call)
}

predicate bufferApi(FunctionCall call) {
  call.getTarget().hasGlobalName([
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat", "sprintf",
    "snprintf", "vsprintf", "vsnprintf", "wmemcpy", "wmemmove", "wcscpy", "wcsncpy",
    "wcscat", "wcsncat"
  ])
}

from FunctionCall buffer, Function f, FunctionCall input
where
  bufferApi(buffer) and
  f = buffer.getEnclosingFunction() and
  input.getEnclosingFunction() = f and
  inputApi(input)
select buffer,
  "Buffer operation in a function that also reads external input. Combined taint + buffer signal."
