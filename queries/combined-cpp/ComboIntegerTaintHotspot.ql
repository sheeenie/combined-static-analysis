/**
 * @name Integer arithmetic in function with external input
 * @description Flags arithmetic performed in a function that also reads external input. This broad combination rule is expected to produce richer, noisier integer-taint results.
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
}

predicate relevantFile(Expr e) {
  exists(string path |
    path = e.getFile().getRelativePath() and
    (path.matches("%CWE190%") or path.matches("%CWE191%") or path.matches("%CWE681%") or
      path.matches("%CWE682%"))
  )
}

from Expr arithmetic, Function f, FunctionCall input
where
  arithmeticExpr(arithmetic) and
  relevantFile(arithmetic) and
  f = arithmetic.getEnclosingFunction() and
  input.getEnclosingFunction() = f and
  inputApi(input)
select arithmetic,
  "This arithmetic expression is in a function that also reads external input, combining integer and taint signals."
