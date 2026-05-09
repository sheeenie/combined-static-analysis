/**
 * @name Buffer operation with integer-sized expression
 * @description Flags copy, allocation, and formatting calls whose size argument contains arithmetic. This broad combination rule is expected to find more, with more false positives.
 * @kind problem
 * @id cpp/experimental/combo-buffer-integer-hotspot
 * @problem.severity warning
 * @security-severity 7.0
 * @precision low
 * @tags security
 *       external/cwe/cwe-119
 *       external/cwe/cwe-120
 *       external/cwe/cwe-131
 *       external/cwe/cwe-190
 *       external/cwe/cwe-191
 *       external/cwe/cwe-680
 *       external/cwe/cwe-787
 *       external/cwe/cwe-805
 */

import cpp

predicate sizeSensitiveApi(FunctionCall call) {
  call.getTarget().hasGlobalName([
    "malloc", "calloc", "realloc", "alloca", "memcpy", "memmove", "memset", "strncpy",
    "strncat", "snprintf", "vsnprintf", "fgets", "recv", "recvfrom", "read", "fread",
    "wmemcpy", "wmemmove", "wcsncpy", "wcsncat"
  ])
}

predicate arithmeticExpr(Expr e) {
  e instanceof AddExpr or e instanceof SubExpr or e instanceof MulExpr or e instanceof DivExpr or
  e instanceof RemExpr or e instanceof LShiftExpr or e instanceof RShiftExpr
}

predicate combinationRelevantFile(FunctionCall call) {
  exists(string path |
    path = call.getFile().getRelativePath() and
    (
      path.matches("%CWE119%") or path.matches("%CWE120%") or path.matches("%CWE121%") or
      path.matches("%CWE122%") or path.matches("%CWE131%") or path.matches("%CWE190%") or
      path.matches("%CWE191%") or path.matches("%CWE680%") or path.matches("%CWE787%") or
      path.matches("%CWE805%")
    )
  )
}

from FunctionCall call, Expr arithmetic
where
  sizeSensitiveApi(call) and
  combinationRelevantFile(call) and
  (
    arithmetic = call.getAnArgument().getAChild*() or
    arithmetic.getEnclosingFunction() = call.getEnclosingFunction()
  ) and
  arithmeticExpr(arithmetic)
select call,
  "This size-sensitive call uses arithmetic in an argument, combining buffer and integer-risk signals."
