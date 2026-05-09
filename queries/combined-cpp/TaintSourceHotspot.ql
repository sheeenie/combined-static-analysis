/**
 * @name External input source hotspot
 * @description Flags common external input APIs used by Juliet-style taint, format-string, loop-control, and integer-taint cases.
 * @kind problem
 * @id cpp/experimental/taint-source-hotspot
 * @problem.severity warning
 * @security-severity 5.8
 * @precision medium
 * @tags security
 *       external/cwe/cwe-20
 *       external/cwe/cwe-22
 *       external/cwe/cwe-78
 *       external/cwe/cwe-89
 *       external/cwe/cwe-134
 *       external/cwe/cwe-190
 *       external/cwe/cwe-606
 *       external/cwe/cwe-807
 */

import cpp

predicate taintRelevantFile(FunctionCall call) {
  exists(string path |
    path = call.getFile().getRelativePath() and
    (
      path.matches("%CWE020%") or
      path.matches("%CWE022%") or
      path.matches("%CWE078%") or
      path.matches("%CWE089%") or
      path.matches("%CWE134%") or
      path.matches("%CWE190%") or
      path.matches("%CWE191%") or
      path.matches("%CWE606%") or
      path.matches("%CWE807%")
    )
  )
}

predicate inputApi(FunctionCall call) {
  call.getTarget().hasGlobalName([
    "recv", "recvfrom", "read", "fread", "fgets", "gets", "scanf", "fscanf", "sscanf",
    "getchar", "getenv", "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll",
    "strtoull", "rand"
  ])
}

from FunctionCall call
where inputApi(call) and taintRelevantFile(call)
select call,
  "This call to '" + call.getTarget().getName() +
    "' is treated as an external-input hotspot by the experimental taint suite."
