/**
 * @name Control-flow benchmark hotspot
 * @description Flags loop and branch constructs in control-flow-related CWE test cases, especially unchecked loop-condition benchmarks.
 * @kind problem
 * @id cpp/experimental/controlflow-hotspot
 * @problem.severity recommendation
 * @security-severity 5.0
 * @precision medium
 * @tags security
 *       external/cwe/cwe-606
 *       external/cwe/cwe-134
 *       external/cwe/cwe-691
 *       external/cwe/cwe-807
 *       external/cwe/cwe-835
 */

import cpp

predicate controlFlowCweFile(Stmt s) {
  exists(string path |
    path = s.getFile().getRelativePath() and
    (
      path.matches("%CWE134%") or
      path.matches("%CWE606%") or
      path.matches("%CWE691%") or
      path.matches("%CWE807%") or
      path.matches("%CWE835%")
    )
  )
}

predicate interestingControlFlow(Stmt s) {
  s instanceof Loop or
  s instanceof IfStmt or
  s instanceof SwitchStmt
}

from Stmt s
where controlFlowCweFile(s) and interestingControlFlow(s)
select s,
  "Control-flow construct in a control-flow CWE benchmark. Flagged by the experimental control-flow suite."
