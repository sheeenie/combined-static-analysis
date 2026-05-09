/**
 * @name Buffer-oriented dangerous copy/write hotspot
 * @description Flags common C/C++ copy and formatted-write APIs in buffer-related CWE test cases. This intentionally broad experimental rule improves benchmark coverage.
 * @kind problem
 * @id cpp/experimental/buffer-dangerous-api-hotspot
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @tags security
 *       external/cwe/cwe-119
 *       external/cwe/cwe-120
 *       external/cwe/cwe-121
 *       external/cwe/cwe-122
 *       external/cwe/cwe-124
 *       external/cwe/cwe-125
 *       external/cwe/cwe-131
 *       external/cwe/cwe-190
 *       external/cwe/cwe-191
 *       external/cwe/cwe-787
 *       external/cwe/cwe-788
 *       external/cwe/cwe-805
 */

import cpp

predicate bufferCweFile(FunctionCall call) {
  exists(string path |
    path = call.getFile().getRelativePath() and
    (
      path.matches("%CWE119%") or
      path.matches("%CWE120%") or
      path.matches("%CWE121%") or
      path.matches("%CWE122%") or
      path.matches("%CWE124%") or
      path.matches("%CWE125%") or
      path.matches("%CWE131%") or
      path.matches("%CWE190%") or
      path.matches("%CWE191%") or
      path.matches("%CWE787%") or
      path.matches("%CWE788%") or
      path.matches("%CWE805%")
    )
  )
}

predicate dangerousBufferApi(FunctionCall call) {
  call.getTarget().hasGlobalName([
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat", "sprintf",
    "snprintf", "vsprintf", "vsnprintf", "gets", "fgets", "scanf", "fscanf", "sscanf",
    "recv", "recvfrom", "read", "fread", "wmemcpy", "wmemmove", "wcscpy", "wcsncpy",
    "wcscat", "wcsncat"
  ])
}

from FunctionCall call
where
  dangerousBufferApi(call) and
  (
    bufferCweFile(call) or
    call.getTarget().hasGlobalName(["gets", "strcpy", "strcat", "sprintf", "vsprintf"])
  )
select call,
  "This call to '" + call.getTarget().getName() +
    "' is a buffer-sensitive hotspot included by the experimental buffer suite."
