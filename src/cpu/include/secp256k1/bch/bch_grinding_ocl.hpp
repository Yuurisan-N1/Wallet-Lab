// =============================================================================
// bch_grinding_ocl.hpp — BCH RPA OpenCL EC Grinding API
// =============================================================================
// Finds a signature nonce k such that:
//   SHA256(SHA256(compact_sig(k)))[0:prefix_bits] == paycode_prefix
//
// Algorithm: hedged RFC 6979 nonce → CT ECDSA sign → double-SHA256 → prefix check
// GPU throughput: expected ~30-100M attempts/s (depends on GPU and prefix length)
//
// Requires: SECP256K1_BUILD_BCH=ON, SECP256K1_BUILD_OPENCL=ON
// =============================================================================

#pragma once

#include <cstdint>
#include <string>

namespace secp256k1::bch {

// Result of one rpa_grind_ocl() call.
struct RpaGrindOCLResult {
    bool     found  = false;          // true if a matching nonce was found
    uint32_t nonce  = 0;              // winning nonce value (valid only if found)
    uint8_t  sig64[64]{};             // compact sig (r || s, 64 bytes) on match
    std::string error;                // non-empty on init/build/runtime failure
};

// Run the BCH RPA EC grinding kernel on an OpenCL device.
//
// sk32         — 32-byte sender private key (caller must erase after return)
// msg32        — 32-byte sighash of the transaction input
// prefix_bits  — number of prefix bits to match (0, 8, 16, or 24)
// prefix_data  — first ceil(prefix_bits/8) bytes of the target prefix
// kernel_dir   — path to the directory containing the .cl kernel files
//                (points to src/opencl/kernels/ in typical builds)
// max_attempts — max nonces to try (0 = unlimited — runs until match)
// platform_id  — OpenCL platform index (0 = first)
// device_id    — OpenCL device index on the selected platform (0 = first)
// batch_size   — work-items per kernel launch (0 = 1M default)
// local_work_size — workgroup size (0 = auto/64)
//
// Returns: RpaGrindOCLResult with found=true and the winning sig on success.
// Security: the private key device buffer is zeroed before release (Rule 10).
RpaGrindOCLResult rpa_grind_ocl(
    const uint8_t  sk32[32],
    const uint8_t  msg32[32],
    uint8_t        prefix_bits,
    const uint8_t  prefix_data[4],
    const char*    kernel_dir       = ".",
    uint32_t       max_attempts     = 0,
    int            platform_id      = 0,
    int            device_id        = 0,
    std::size_t    batch_size       = 0,
    std::size_t    local_work_size  = 0);

} // namespace secp256k1::bch
