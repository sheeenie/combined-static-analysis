#!/usr/bin/env bash
set -euo pipefail

# Build whichever libpng tag has been checked out.
# Release tags (e.g. v1.6.37, v1.2.53) ship a generated `configure`.
# Source-only tags (e.g. v1.6.34) ship only configure.ac + autogen.sh, which
# need autotools. To avoid that dependency we fall back to the hand-written
# scripts/makefile.linux against the system zlib.
# CodeQL only needs the compiler to run on the .c files; whether the resulting
# .so or .a actually links is not important here.

if [ -x ./configure ]; then
  ./configure --disable-shared --enable-static
  make -j"$(nproc)"
  exit 0
fi

if [ -f scripts/makefile.linux ]; then
  # libpng >= 1.5 needs a pnglibconf.h. The repo ships a prebuilt copy.
  if [ -f scripts/pnglibconf.h.prebuilt ] && [ ! -f pnglibconf.h ]; then
    cp scripts/pnglibconf.h.prebuilt pnglibconf.h
  fi

  zlib_h="$(find /usr/include /usr/local/include -name zlib.h 2>/dev/null | head -1)"
  zlib_so="$(ldconfig -p 2>/dev/null | awk '/libz\.so / {print $NF; exit}')"
  zlib_inc="${zlib_h:+$(dirname "$zlib_h")}"
  zlib_lib="${zlib_so:+$(dirname "$zlib_so")}"

  make -f scripts/makefile.linux \
    ZLIBINC="${zlib_inc:-/usr/include}" \
    ZLIBLIB="${zlib_lib:-/usr/lib}" \
    CC=gcc \
    -j"$(nproc)"
  exit 0
fi

echo "build_libpng.sh: no build entrypoint found (no configure, no scripts/makefile.linux)" >&2
exit 1
