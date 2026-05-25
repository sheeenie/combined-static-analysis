/**
 * @name Control-flow construct in function with external input
 * @description Flags loop and branch constructs in functions that also read external input. Broad combination rule for the taint + control-flow pair.
 * @kind problem
 * @id cpp/experimental/combo-taint-controlflow-hotspot
 * @problem.severity warning
 * @security-severity 6.8
 * @precision low
 * @tags security
 *       external/cwe/cwe-20
 *       external/cwe/cwe-606
 *       external/cwe/cwe-691
 *       external/cwe/cwe-807
 *       external/cwe/cwe-835
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

predicate controlFlowStmt(Stmt s) {
  s instanceof Loop or s instanceof IfStmt or s instanceof SwitchStmt
}

from Stmt s, Function f, FunctionCall input
where
  controlFlowStmt(s) and
  f = s.getEnclosingFunction() and
  input.getEnclosingFunction() = f and
  inputApi(input)
select s,
  "Control-flow construct in a function that also reads external input. Combined taint + control-flow signal."
