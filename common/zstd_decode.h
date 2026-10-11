// Copyright (C) 2026 AERA Recovery Project contributors
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <zstd.h>

namespace chromeos_update_engine {
// Decode exactly one complete frame with bounded memory and output. The sink
// receives small chunks; never allocate a whole partition or trust frame size.
template <typename Sink>
bool DecodeZstd(const void* data, size_t size, uint64_t expected, Sink sink) {
  std::unique_ptr<ZSTD_DCtx, decltype(&ZSTD_freeDCtx)> ctx(
      ZSTD_createDCtx(), ZSTD_freeDCtx);
  if (!ctx || !size || !expected ||
      ZSTD_isError(ZSTD_DCtx_setParameter(ctx.get(), ZSTD_d_windowLogMax, 27)))
    return false;
  ZSTD_inBuffer input{data, size, 0};
  std::array<unsigned char, 65536> buffer;
  uint64_t total = 0;
  for (;;) {
    ZSTD_outBuffer output{buffer.data(), buffer.size(), 0};
    const auto before = input.pos;
    const size_t result = ZSTD_decompressStream(ctx.get(), &output, &input);
    if (ZSTD_isError(result) || output.pos > expected - total) return false;
    if (output.pos && !sink(buffer.data(), output.pos)) return false;
    total += output.pos;
    if (!result) return input.pos == size && total == expected;
    if (input.pos == before && !output.pos) return false;
  }
}
}  // namespace chromeos_update_engine
