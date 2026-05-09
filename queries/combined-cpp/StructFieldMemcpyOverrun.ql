/**
 * @name Memory copy writes past a struct field
 * @description A memory-copy call writes more bytes than the destination struct field can hold, often caused by using sizeof on the enclosing struct instead of the field.
 * @kind problem
 * @id cpp/struct-field-memcpy-overrun
 * @problem.severity warning
 * @security-severity 8.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-119
 *       external/cwe/cwe-121
 *       external/cwe/cwe-122
 */

import cpp

/**
 * Gets a field access used as the destination object in `memcpy` or `memmove`.
 *
 * The destination argument may contain implicit conversions, so look through
 * the argument's expression tree rather than requiring the argument itself to
 * be the field access.
 */
FieldAccess getDestinationFieldAccess(FunctionCall call) {
  call.getTarget().hasGlobalName(["memcpy", "memmove"]) and
  result = call.getArgument(0).getAChild*()
}

from FunctionCall call, FieldAccess dest, int destSize, int copySize
where
  dest = getDestinationFieldAccess(call) and
  destSize = dest.getTarget().getType().getSize() and
  copySize = call.getArgument(2).getValue().toInt() and
  copySize > destSize
select call,
  "This " + call.getTarget().getName() + " writes " + copySize + " bytes into field '" +
    dest.getTarget().getName() +
    "', which is only " + destSize + " bytes. Use the field size rather than the enclosing object size."
