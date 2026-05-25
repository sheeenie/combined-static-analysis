/**
 * @name Integer arithmetic hotspot
 * @description Flags arithmetic operations in integer-related CWE test cases. Broad rule used by the experimental integer suite to give isolated runs benchmark signal.
 * @kind problem
 * @id cpp/experimental/integer-arithmetic-hotspot
 * @problem.severity warning
 * @security-severity 6.0
 * @precision medium
 * @tags security
 *       external/cwe/cwe-190
 *       external/cwe/cwe-191
 *       external/cwe/cwe-369
 *       external/cwe/cwe-681
 *       external/cwe/cwe-682
 *       external/cwe/cwe-839
 */

import cpp

predicate integerCweFile(Expr e) {
  exists(string path |
    path = e.getFile().getRelativePath() and
    (
      path.matches("%CWE190%") or
      path.matches("%CWE191%") or
      path.matches("%CWE369%") or
      path.matches("%CWE681%") or
      path.matches("%CWE682%") or
      path.matches("%CWE839%")
    )
  )
}

predicate interestingArithmetic(Expr e) {
  e instanceof AddExpr or
  e instanceof SubExpr or
  e instanceof MulExpr or
  e instanceof DivExpr or
  e instanceof RemExpr or
  e instanceof LShiftExpr or
  e instanceof RShiftExpr
}

from Expr e
where integerCweFile(e) and interestingArithmetic(e)
select e,
  "Arithmetic in an integer-related CWE benchmark. Flagged by the experimental integer suite."
