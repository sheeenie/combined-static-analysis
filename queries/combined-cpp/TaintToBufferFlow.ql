/**
 * @name User input reaches a buffer-write size or index
 * @description Chained taint to buffer analysis. Reports a data-flow path
 *              from a user-input source (recv, fgets, scanf, argv, getenv,
 *              libpng wrappers) to the size argument of a copy/format API,
 *              the index of an array write, or a tainted-integer comparison
 *              that gates a size check.
 * @kind path-problem
 * @id cpp/experimental/taint-to-buffer-flow
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @tags security
 *       external/cwe/cwe-20
 *       external/cwe/cwe-119
 *       external/cwe/cwe-120
 *       external/cwe/cwe-121
 *       external/cwe/cwe-122
 *       external/cwe/cwe-129
 *       external/cwe/cwe-787
 *       external/cwe/cwe-805
 */

import cpp
import semmle.code.cpp.security.FlowSources as FS
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.controlflow.IRGuards
import LibpngSources
import TaintToBufferFlow::PathGraph

predicate isFlowSource(FS::FlowSource source, string sourceType) {
  sourceType = source.getSourceType()
}

// Stock FlowSources OR libpng-specific sources. The libpng additions are what
// give the data-flow query nonzero hits on PNG decoder code.
predicate isAnySource(DataFlow::Node source, string sourceType) {
  isFlowSource(source, sourceType)
  or
  libpngFlowSource(source, sourceType)
}

// Holds if `call` is a size-sensitive buffer/format API and `argIndex` is the
// 0-based index of its size argument.
predicate sizeArgOf(FunctionCall call, int argIndex) {
  call.getTarget().hasGlobalName(["memcpy", "memmove", "memset", "wmemcpy", "wmemmove", "wmemset"]) and
    argIndex = 2
  or
  call.getTarget().hasGlobalName(["strncpy", "strncat", "wcsncpy", "wcsncat"]) and argIndex = 2
  or
  call.getTarget().hasGlobalName(["snprintf", "vsnprintf"]) and argIndex = 1
  or
  call.getTarget().hasGlobalName(["malloc", "alloca"]) and argIndex = 0
  or
  call.getTarget().hasGlobalName(["calloc"]) and argIndex in [0 .. 1]
  or
  call.getTarget().hasGlobalName(["realloc"]) and argIndex = 1
  or
  call.getTarget().hasGlobalName(["fgets", "fread"]) and argIndex = 1
  or
  call.getTarget().hasGlobalName(["recv", "recvfrom", "read"]) and argIndex = 2
}

// Upper-bound check on `e`, used as a sanitiser barrier. Mirrors the pattern
// used in ImproperArrayIndexValidation.ql.
predicate guardChecks(IRGuardCondition g, Expr e, boolean branch) {
  exists(Operand op | op.getDef().getConvertedResultExpression() = e |
    g.comparesLt(op, any(int k | k > 0), true, any(GuardValue bv | bv.asBooleanValue() = branch))
    or
    g.comparesLt(op, _, any(int k | k > 0), true, branch)
    or
    g.comparesEq(op, _, true, any(GuardValue bv | bv.asBooleanValue() = branch))
    or
    g.comparesEq(op, _, _, true, branch)
  )
}

module TaintToBufferConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isAnySource(source, _) }

  predicate isBarrier(DataFlow::Node node) {
    node = DataFlow::BarrierGuard<guardChecks/3>::getABarrierNode()
  }

  predicate isSink(DataFlow::Node sink) {
    // Size/length argument of a buffer/format/alloc API.
    exists(FunctionCall call, int i |
      sizeArgOf(call, i) and
      sink.asExpr() = call.getArgument(i)
    )
    or
    // Index expression of an array write.
    exists(ArrayExpr ae | sink.asExpr() = ae.getArrayOffset())
    or
    // Tainted integer used as an operand of a bounds/size comparison whose
    // other operand is itself computed at runtime (not a literal). Matches
    // the shape of CVE-2018-13785 in libpng, where a chunk length is
    // compared against an arithmetic expression that can wrap, so the guard
    // is bypassed before the tainted value reaches a memcpy size argument.
    exists(ComparisonOperation cmp, Expr other |
      sink.asExpr() = cmp.getAnOperand() and
      other = cmp.getAnOperand() and
      other != sink.asExpr() and
      not other instanceof Literal and
      sink.asExpr().getType().getUnspecifiedType() instanceof IntegralType
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module TaintToBufferFlow = TaintTracking::Global<TaintToBufferConfig>;

// Short description of the sink, used in the result message.
string sinkKind(DataFlow::Node sink) {
  exists(FunctionCall call, int i |
    sizeArgOf(call, i) and
    sink.asExpr() = call.getArgument(i) and
    result = "the size argument of " + call.getTarget().getName() + "()"
  )
  or
  exists(ArrayExpr ae |
    sink.asExpr() = ae.getArrayOffset() and
    result = "an array index"
  )
  or
  exists(ComparisonOperation cmp |
    sink.asExpr() = cmp.getAnOperand() and
    result = "an integer-comparison guard (" + cmp.getOperator() + ")"
  )
}

from TaintToBufferFlow::PathNode source, TaintToBufferFlow::PathNode sink, string sourceType
where
  TaintToBufferFlow::flowPath(source, sink) and
  isAnySource(source.getNode(), sourceType)
select sink.getNode(), source, sink,
  "User input from $@ flows to " + sinkKind(sink.getNode()) +
    "; the write/index may be attacker-controlled.",
  source.getNode(), sourceType
