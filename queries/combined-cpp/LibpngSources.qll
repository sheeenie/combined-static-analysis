/**
 * libpng-specific taint sources for the combined-static-analysis pack.
 *
 * libpng reads attacker-controlled bytes through its own wrappers
 * (png_read_data, png_get_uint_*, chunk-handler length parameters), not by
 * calling libc input APIs at the bug sites. The stock FlowSources model does
 * not know about those wrappers, so without this file the data-flow queries
 * find no source-to-sink path on libpng.
 *
 * Two predicates are exposed:
 *   libpngFlowSource - data-flow source nodes (used by TaintToBufferFlow.ql)
 *   libpngInputApi   - same-function trigger used by the syntactic hotspots
 *
 * libpngFlowSource is a predicate rather than a RemoteFlowSource subclass
 * because the pack uses the new-style AST DataFlow API, not the IR one that
 * RemoteFlowSource is built against.
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

predicate libpngFlowSource(DataFlow::Node source, string sourceType) {
  // Output buffer of png_read_data(png_ptr, buf, length) and friends. The
  // function dispatches through png_ptr->read_data_fn, which by default wraps
  // fread on the PNG input stream.
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
  // The `length` / `size` parameter of png_handle_* and the chunk-length
  // helpers. These come from the on-disk chunk header.
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
  // Byte-order conversion helpers that parse on-disk fields out of read buffers.
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
 * Same-function trigger used by the syntactic hotspot queries. Holds for any
 * call to a libpng input or parse helper. For data-flow, use libpngFlowSource.
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
