/**
 * @name User input reaches a buffer-write size or index
 * @description Chained taint→buffer analysis. Reports an actual data-flow path
 *              from a user-input source (recv, fgets, scanf, argv, getenv, ...)
 *              to the size argument of a copy/format API or the index of an
 *              array write. Unlike the syntactic co-occurrence combo, a finding
 *              here means the unsafe write is reachable from attacker input.
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

/**
 * Stock FlowSources OR libpng-specific sources. The libpng additions are
 * what give the data-flow query nonzero hits on PNG decoder code; without
 * them, `fread` is reached only through `png_read_data`'s function pointer
 * and the stock model does not bridge that indirection.
 */
predicate isAnySource(DataFlow::Node source, string sourceType) {
  isFlowSource(source, sourceType)
  or
  libpngFlowSource(source, sourceType)
}

/**
 * Holds if `call` is a size-sensitive buffer/format API and `argIndex` is the
 * 0-based index of its size argument.
 */
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

/**
 * A guard that imposes some upper-bound check on `e`, acting as a sanitizer.
 * Mirrors the barrier used in `ImproperArrayIndexValidation.ql`: if the value
 * is compared against a positive constant, or against another value `+ k`,
 * with `k > 0`, downstream uses are treated as sanitized.
 */
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
    // Integer-guard sink: a tainted integer used as an operand of a
    // size/bounds comparison. This is the sink shape for CWE-190 bugs
    // where the wrap happens inside the bounds-check arithmetic itself
    // (CVE-2018-13785 in libpng is the motivating example: a chunk
    // length is compared against a value derived from arithmetic that
    // can wrap, so the guard is bypassed without the tainted value ever
    // reaching a `memcpy` size argument). To suppress trivial flag-vs-
    // constant checks, require the *other* operand to be a non-literal
    // expression — i.e. itself computed at runtime.
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

/**
 * Short description of what the sink represents, used in the result message
 * to distinguish array-index sinks from buffer-size sinks.
 */
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
