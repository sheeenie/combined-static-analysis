/**
 * @name Integer arithmetic in function with external input
 * @description Flags arithmetic performed in a function that also reads external input. Broad combination rule with higher recall and more false positives than the isolated suites.
 * @kind problem
 * @id cpp/experimental/combo-integer-taint-hotspot
 * @problem.severity warning
 * @security-severity 7.0
 * @precision low
 * @tags security
 *       external/cwe/cwe-20
 *       external/cwe/cwe-190
 *       external/cwe/cwe-191
 *       external/cwe/cwe-681
 *       external/cwe/cwe-682
 */

import cpp
import LibpngSources

predicate arithmeticExpr(Expr e) {
  e instanceof AddExpr or e instanceof SubExpr or e instanceof MulExpr or e instanceof DivExpr or
  e instanceof RemExpr or e instanceof LShiftExpr or e instanceof RShiftExpr
}

predicate inputApi(FunctionCall call) {
  call.getTarget().hasGlobalName([
    "recv", "recvfrom", "read", "fread", "fgets", "gets", "scanf", "fscanf", "sscanf",
    "getchar", "getenv", "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll",
    "strtoull", "rand"
  ])
  or
  libpngInputApi(call)
}

from Expr arithmetic, Function f, FunctionCall input
where
  arithmeticExpr(arithmetic) and
  f = arithmetic.getEnclosingFunction() and
  input.getEnclosingFunction() = f and
  inputApi(input)
select arithmetic,
  "Arithmetic in a function that also reads external input. Combined integer + taint signal."
