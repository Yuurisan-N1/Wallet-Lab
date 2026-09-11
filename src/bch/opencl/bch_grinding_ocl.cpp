// =============================================================================
// bch_grinding_ocl.cpp — BCH RPA EC Grinding host-side OpenCL launcher
// =============================================================================
// Loads secp256k1_bch_grinding.cl (and its dependencies) from the kernel
// source directory, builds the OpenCL program, and runs rpa_grind_kernel in
// batches until a prefix match is found or max_attempts is exhausted.
//
// Security: the private key buffer is zeroed before release (Rule 10).
// =============================================================================

#define CL_TARGET_OPENCL_VERSION 120
#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#ifdef __APPLE__
#  include <OpenCL/cl.h>
#else
#  include <CL/cl.h>
#endif

#include "secp256k1/bch/bch_grinding_ocl.hpp"
#include "secp256k1/detail/secure_erase.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>

namespace secp256k1::bch {

// ── Kernel source loading ────────────────────────────────────────────────────

static std::string read_file(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string load_grinding_source(const char* kernel_dir) {
    // Ordered dependency chain — each file #includes the previous.
    // The grinding kernel is the last entry.
    const char* files[] = {
        "secp256k1_field.cl",
        "secp256k1_point.cl",
        "secp256k1_extended.cl",
        "secp256k1_hash160.cl",
        "secp256k1_ct_ops.cl",
        "secp256k1_ct_field.cl",
        "secp256k1_ct_scalar.cl",
        "secp256k1_ct_point.cl",
        "secp256k1_ct_sign.cl",
        "secp256k1_bch_grinding.cl",
        nullptr
    };

    std::string src;
    for (int i = 0; files[i]; ++i) {
        char path[512];
        std::snprintf(path, sizeof(path), "%s/%s", kernel_dir, files[i]);
        std::string content = read_file(path);
        if (content.empty()) {
            std::fprintf(stderr, "[bch_grinding_ocl] missing kernel: %s\n", path);
            return {};
        }
        src += content;
        src += "\n";
    }
    return src;
}

// ── OpenCL grinding context ──────────────────────────────────────────────────

struct RpaGrindOCLContext {
    cl_platform_id  platform = nullptr;
    cl_device_id    device   = nullptr;
    cl_context      ctx      = nullptr;
    cl_command_queue queue   = nullptr;
    cl_program      program  = nullptr;
    cl_kernel       kernel   = nullptr;

    cl_mem buf_sk     = nullptr;   // 32-byte private key (secret, zeroed on exit)
    cl_mem buf_msg    = nullptr;   // 32-byte message hash
    cl_mem buf_prefix = nullptr;   // 4-byte prefix data
    cl_mem buf_nonce  = nullptr;   // int32_t result nonce (-1 = not found)
    cl_mem buf_sig    = nullptr;   // 64-byte result signature

    ~RpaGrindOCLContext() {
        // Rule 10: zero private key in device memory before releasing
        if (queue && buf_sk) {
            cl_uchar zero = 0;
            clEnqueueFillBuffer(queue, buf_sk, &zero, 1, 0, 32, 0, nullptr, nullptr);
            clFinish(queue);
        }
        if (buf_sk)     clReleaseMemObject(buf_sk);
        if (buf_msg)    clReleaseMemObject(buf_msg);
        if (buf_prefix) clReleaseMemObject(buf_prefix);
        if (buf_nonce)  clReleaseMemObject(buf_nonce);
        if (buf_sig)    clReleaseMemObject(buf_sig);
        if (kernel)     clReleaseKernel(kernel);
        if (program)    clReleaseProgram(program);
        if (queue)      clReleaseCommandQueue(queue);
        if (ctx)        clReleaseContext(ctx);
    }
};

// ── Public API ───────────────────────────────────────────────────────────────

RpaGrindOCLResult rpa_grind_ocl(
    const uint8_t  sk32[32],
    const uint8_t  msg32[32],
    uint8_t        prefix_bits,
    const uint8_t  prefix_data[4],
    const char*    kernel_dir,
    uint32_t       max_attempts,
    int            platform_id,
    int            device_id,
    size_t         batch_size,
    size_t         local_work_size)
{
    RpaGrindOCLResult result{};

    // ── 1. Platform / device selection ────────────────────────────────────────
    cl_uint nplatforms = 0;
    clGetPlatformIDs(0, nullptr, &nplatforms);
    if (nplatforms == 0) {
        result.error = "no OpenCL platforms found";
        return result;
    }
    std::vector<cl_platform_id> platforms(nplatforms);
    clGetPlatformIDs(nplatforms, platforms.data(), nullptr);

    if (platform_id < 0 || (cl_uint)platform_id >= nplatforms) {
        result.error = "invalid platform_id";
        return result;
    }
    cl_platform_id plat = platforms[(size_t)platform_id];

    cl_uint ndevices = 0;
    clGetDeviceIDs(plat, CL_DEVICE_TYPE_ALL, 0, nullptr, &ndevices);
    if (ndevices == 0) {
        result.error = "no OpenCL devices on platform";
        return result;
    }
    std::vector<cl_device_id> devices(ndevices);
    clGetDeviceIDs(plat, CL_DEVICE_TYPE_ALL, ndevices, devices.data(), nullptr);

    if (device_id < 0 || (cl_uint)device_id >= ndevices) {
        result.error = "invalid device_id";
        return result;
    }

    RpaGrindOCLContext ocl;
    ocl.device   = devices[(size_t)device_id];
    ocl.platform = plat;

    // ── 2. Create context + queue ──────────────────────────────────────────────
    cl_int err = CL_SUCCESS;
    ocl.ctx   = clCreateContext(nullptr, 1, &ocl.device, nullptr, nullptr, &err);
    if (err != CL_SUCCESS) { result.error = "clCreateContext failed"; return result; }

    ocl.queue = clCreateCommandQueue(ocl.ctx, ocl.device, 0, &err);
    if (err != CL_SUCCESS) { result.error = "clCreateCommandQueue failed"; return result; }

    // ── 3. Load and build kernel source ───────────────────────────────────────
    std::string src = load_grinding_source(kernel_dir);
    if (src.empty()) { result.error = "failed to load kernel source"; return result; }

    const char* src_ptr = src.c_str();
    size_t src_len = src.size();
    ocl.program = clCreateProgramWithSource(ocl.ctx, 1, &src_ptr, &src_len, &err);
    if (err != CL_SUCCESS) { result.error = "clCreateProgramWithSource failed"; return result; }

    err = clBuildProgram(ocl.program, 1, &ocl.device,
                         "-cl-std=CL1.2 -cl-fast-relaxed-math", nullptr, nullptr);
    if (err != CL_SUCCESS) {
        size_t log_size = 0;
        clGetProgramBuildInfo(ocl.program, ocl.device,
                              CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        std::string log(log_size, '\0');
        clGetProgramBuildInfo(ocl.program, ocl.device,
                              CL_PROGRAM_BUILD_LOG, log_size, log.data(), nullptr);
        result.error = "build error: " + log;
        return result;
    }

    ocl.kernel = clCreateKernel(ocl.program, "rpa_grind_kernel", &err);
    if (err != CL_SUCCESS) { result.error = "clCreateKernel failed"; return result; }

    // ── 4. Allocate device buffers ─────────────────────────────────────────────
    ocl.buf_sk     = clCreateBuffer(ocl.ctx, CL_MEM_READ_ONLY,  32, nullptr, &err);
    ocl.buf_msg    = clCreateBuffer(ocl.ctx, CL_MEM_READ_ONLY,  32, nullptr, &err);
    ocl.buf_prefix = clCreateBuffer(ocl.ctx, CL_MEM_READ_ONLY,  4,  nullptr, &err);
    ocl.buf_nonce  = clCreateBuffer(ocl.ctx, CL_MEM_READ_WRITE, sizeof(int32_t), nullptr, &err);
    ocl.buf_sig    = clCreateBuffer(ocl.ctx, CL_MEM_READ_WRITE, 64, nullptr, &err);
    if (!ocl.buf_sk || !ocl.buf_msg || !ocl.buf_prefix ||
        !ocl.buf_nonce || !ocl.buf_sig) {
        result.error = "clCreateBuffer failed";
        return result;
    }

    // ── 5. Upload constant inputs ──────────────────────────────────────────────
    clEnqueueWriteBuffer(ocl.queue, ocl.buf_sk,     CL_TRUE, 0, 32, sk32,        0, nullptr, nullptr);
    clEnqueueWriteBuffer(ocl.queue, ocl.buf_msg,    CL_TRUE, 0, 32, msg32,       0, nullptr, nullptr);
    clEnqueueWriteBuffer(ocl.queue, ocl.buf_prefix, CL_TRUE, 0, 4,  prefix_data, 0, nullptr, nullptr);

    // ── 6. Grinding loop ───────────────────────────────────────────────────────
    size_t local_size = (local_work_size == 0) ? 64 : local_work_size;
    if (batch_size == 0) batch_size = 1u << 20;  // 1M per batch

    uint32_t base = 0;

    while (true) {
        uint32_t n = (max_attempts > 0)
            ? (uint32_t)std::min((uint64_t)(max_attempts - base), (uint64_t)batch_size)
            : (uint32_t)batch_size;

        // Initialise result nonce to -1
        int32_t neg1 = -1;
        clEnqueueWriteBuffer(ocl.queue, ocl.buf_nonce, CL_TRUE, 0,
                             sizeof(int32_t), &neg1, 0, nullptr, nullptr);

        // Set kernel arguments
        cl_uchar pf_bits = (cl_uchar)prefix_bits;
        cl_uint  base_n  = (cl_uint)base;
        clSetKernelArg(ocl.kernel, 0, sizeof(cl_mem),   &ocl.buf_sk);
        clSetKernelArg(ocl.kernel, 1, sizeof(cl_mem),   &ocl.buf_msg);
        clSetKernelArg(ocl.kernel, 2, sizeof(cl_uchar), &pf_bits);
        clSetKernelArg(ocl.kernel, 3, sizeof(cl_mem),   &ocl.buf_prefix);
        clSetKernelArg(ocl.kernel, 4, sizeof(cl_uint),  &base_n);
        clSetKernelArg(ocl.kernel, 5, sizeof(cl_mem),   &ocl.buf_nonce);
        clSetKernelArg(ocl.kernel, 6, sizeof(cl_mem),   &ocl.buf_sig);

        // Round global size up to multiple of local size
        size_t global_size = ((n + local_size - 1) / local_size) * local_size;
        clEnqueueNDRangeKernel(ocl.queue, ocl.kernel, 1, nullptr,
                               &global_size, &local_size, 0, nullptr, nullptr);
        clFinish(ocl.queue);

        // Read result
        int32_t found_nonce = -1;
        clEnqueueReadBuffer(ocl.queue, ocl.buf_nonce, CL_TRUE, 0,
                            sizeof(int32_t), &found_nonce, 0, nullptr, nullptr);

        if (found_nonce >= 0) {
            result.found  = true;
            result.nonce  = (uint32_t)found_nonce;
            clEnqueueReadBuffer(ocl.queue, ocl.buf_sig, CL_TRUE, 0,
                                64, result.sig64, 0, nullptr, nullptr);
            break;
        }

        base += n;
        if (max_attempts > 0 && base >= max_attempts) break;
    }

    // Rule 10: device buffer is zeroed in ~RpaGrindOCLContext via clEnqueueFillBuffer.
    // Host caller is responsible for erasing their own sk32 copy.

    return result;
}

} // namespace secp256k1::bch
