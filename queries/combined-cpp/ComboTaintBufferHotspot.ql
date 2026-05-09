/**
 * @name Buffer operation in function with external input
 * @description Flags copy/write calls in functions that also read external input. This broad combination rule complements precise buffer-overrun checks.
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

predicate inputApi(FunctionCall call) {
  call.getTarget().hasGlobalName([
    "recv", "recvfrom", "read", "fread", "fgets", "gets", "scanf", "fscanf", "sscanf",
    "getchar", "getenv", "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll",
    "strtoull"
  ])
}

predicate bufferApi(FunctionCall call) {
  call.getTarget().hasGlobalName([
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat", "sprintf",
    "snprintf", "vsprintf", "vsnprintf", "wmemcpy", "wmemmove", "wcscpy", "wcsncpy",
    "wcscat", "wcsncat"
  ])
}

predicate relevantFile(FunctionCall call) {
  exists(string path |
    path = call.getFile().getRelativePath() and
    (path.matches("%CWE119%") or path.matches("%CWE120%") or path.matches("%CWE121%") or
      path.matches("%CWE122%") or path.matches("%CWE787%") or path.matches("%CWE805%"))
  )
}

from FunctionCall buffer, Function f, FunctionCall input
where
  bufferApi(buffer) and
  relevantFile(buffer) and
  f = buffer.getEnclosingFunction() and
  input.getEnclosingFunction() = f and
  inputApi(input)
select buffer,
  "This buffer operation occurs in a function that also reads external input, combining taint and buffer signals."
