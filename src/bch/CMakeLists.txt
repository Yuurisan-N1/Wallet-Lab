if(NOT SECP256K1_BUILD_BCH)
    return()
endif()
message(STATUS "Secp256k1: BCH module: ON — CashAddr, RPA, scan pipeline")
target_sources(fastsecp256k1 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cashaddr.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/rpa.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bch_scan.cpp)
target_compile_definitions(fastsecp256k1 PUBLIC SECP256K1_BUILD_BCH=1)
target_include_directories(fastsecp256k1 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../cpu/include)

# BCH benchmark binary
if(SECP256K1_BUILD_BENCH)
    add_executable(bench_bch ${CMAKE_CURRENT_SOURCE_DIR}/bench/bench_bch.cpp)
    find_package(Threads REQUIRED)
target_link_libraries(bench_bch PRIVATE fastsecp256k1 Threads::Threads)
    target_include_directories(bench_bch PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../cpu/include)
    target_compile_options(bench_bch PRIVATE -O3 -march=native)
    message(STATUS "  BCH benchmark: bench_bch")
endif()
# RPA example project
if(SECP256K1_BUILD_EXAMPLES)
    find_package(Threads REQUIRED)
    add_executable(rpa_wallet_example
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/rpa_wallet.cpp)
    target_link_libraries(rpa_wallet_example PRIVATE fastsecp256k1 Threads::Threads)
    target_include_directories(rpa_wallet_example PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../cpu/include)
    target_compile_options(rpa_wallet_example PRIVATE -O2)
    message(STATUS "  BCH example: rpa_wallet_example")
endif()
# GPU grinding kernels (per-backend, all off by default)
if(SECP256K1_BUILD_BCH AND SECP256K1_BUILD_CUDA)
    message(STATUS "  BCH GPU: CUDA grinding kernel")
    if(TARGET secp256k1_cuda_lib)
        target_sources(secp256k1_cuda_lib PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/cuda/bch_grinding.cu)
        target_compile_definitions(secp256k1_cuda_lib PUBLIC SECP256K1_BCH_CUDA=1)
    endif()
endif()

# OpenCL grinding kernel + host launcher
if(SECP256K1_BUILD_BCH AND SECP256K1_BUILD_OPENCL)
    find_package(OpenCL QUIET)
    if(OpenCL_FOUND)
        add_library(bch_grinding_ocl STATIC
            ${CMAKE_CURRENT_SOURCE_DIR}/opencl/bch_grinding_ocl.cpp)
        target_include_directories(bch_grinding_ocl PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/../cpu/include)
        target_link_libraries(bch_grinding_ocl
            PUBLIC  fastsecp256k1 OpenCL::OpenCL
            PRIVATE Threads::Threads)
        target_compile_definitions(bch_grinding_ocl PUBLIC SECP256K1_BCH_OPENCL=1)
        message(STATUS "  BCH GPU: OpenCL grinding kernel (secp256k1_bch_grinding.cl)")
    else()
        message(STATUS "  BCH GPU: OpenCL not found — skipping bch_grinding_ocl")
    endif()
endif()

# Metal stub — Metal grinding kernel is macOS/iOS-only (TODO: bch_grinding.metal)
