/**
 * Custom libpng source models for the combined-static-analysis pack.
 *
 * libpng pulls attacker-controlled bytes through its own wrappers
 * (`png_read_data`, `png_get_uint_*`, and the `length` parameter of chunk
 * handlers) rather than calling libc input APIs directly from the bug
 * sites. The stock `semmle.code.cpp.security.FlowSources` model doesn't
 * know about these wrappers, so on libpng the data-flow taint queries
 * see no source-to-sink path. This module adds the missing libpng
 * sources for both the precise data-flow analyses (predicate
 * `libpngFlowSource`) and the broader syntactic hotspot rules
 * (predicate `libpngInputApi`).
 *
 * Why a predicate instead of `extends RemoteFlowSource`:
 * `RemoteFlowSource` is defined against `semmle.code.cpp.ir.dataflow`
 * (IR `DataFlow::Node`), while the queries in this pack use the AST
 * `semmle.code.cpp.dataflow.new` API. Keeping the model as a predicate
 * on the new-style `DataFlow::Node` avoids the IR/AST bridging overhead
 * and lets each query OR this source set into its own `isSource`.
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/**
 * Holds if `source` is a libpng-specific taint source.
 *
 * `sourceType` is a short label suitable for the SARIF result message
 * (mirrors the role of `FlowSource::getSourceType()` in the stock lib).
 */
predicate libpngFlowSource(DataFlow::Node source, string sourceType) {
  // The output buffer of `png_read_data(png_ptr, buf, length)`. The function
  // dispatches through `png_ptr->read_data_fn`, which defaults to a wrapper
  // around `fread` on the PNG input stream. Anything subsequently read from
  // `buf` is attacker-controlled.
  exists(FunctionCall call |
    call.getTarget()
        .hasGlobalName([
            "png_read_data",
            "png_default_read_data",
            "png_crc_read"
          ]) and
    source.asDefiningArgument() = call.getArgument(1) and
    sourceType = "libpng input via " + call.getTarget().getName() + "()"
  )
  or
  // The `length` (or `size`) parameter of chunk-handler entry points such as
  // `png_handle_PLTE`, `png_handle_IHDR`, etc., and of length-check helpers
  // (`png_check_chunk_length`). These values are read directly from the
  // on-disk PNG chunk header before the handler is invoked.
  exists(Function f, Parameter p |
    (
      f.getName().matches("png_handle_%")
      or
      f.getName() = ["png_check_chunk_length", "png_check_user_chunk_length"]
    ) and
    p = f.getAParameter() and
    p.getName().toLowerCase() = ["length", "size"] and
    source.asParameter() = p and
    sourceType = "libpng chunk-length parameter of " + f.getName() + "()"
  )
  or
  // Byte-order conversion helpers that interpret raw input bytes as integers.
  // Used pervasively in libpng to parse on-disk fields out of read buffers.
  exists(FunctionCall call |
    call.getTarget()
        .hasGlobalName([
            "png_get_uint_32", "png_get_uint_16", "png_get_uint_31",
            "png_get_int_32", "png_get_int_16"
          ]) and
    source.asExpr() = call and
    sourceType = "libpng byte-order read via " + call.getTarget().getName() + "()"
  )
}

/**
 * Holds if `call` is a libpng input/parse API call useful for the coarse
 * "function contains attacker input" syntactic hotspots. The hotspots use
 * this as a same-function trigger; data-flow queries should use
 * `libpngFlowSource` instead, which captures the exact source nodes.
 */
predicate libpngInputApi(FunctionCall call) {
  call.getTarget()
      .hasGlobalName([
          "png_read_data", "png_default_read_data",
          "png_get_uint_32", "png_get_uint_16", "png_get_uint_31",
          "png_get_int_32", "png_get_int_16",
          "png_read_chunk_header", "png_crc_read", "png_crc_finish"
        ])
}
