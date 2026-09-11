# ============================================================================
# compat/litecoin_shim — Litecoin Core secp256k1 backend shim
# ============================================================================
# Litecoin Core uses the identical secp256k1.h / secp256k1_schnorrsig.h /
# secp256k1_extrakeys.h API surface as Bitcoin Core.
# This shim delegates entirely to libsecp256k1_shim.
#
# Usage in Litecoin Core cmake:
#   cmake -B build -DSECP256K1_BACKEND=ultrafast
#
# Features supported:
#   secp256k1.h              — context, ECDSA, pubkey
#   secp256k1_extrakeys.h    — xonly pubkeys, keypairs (Taproot)
#   secp256k1_schnorrsig.h   — BIP-340 Schnorr (MWEB + Taproot)
#   secp256k1_ecdh.h         — ECDH
#   secp256k1_recovery.h     — recoverable ECDSA
#   secp256k1_ellswift.h     — ElligatorSwift (future LTC P2P)
#   secp256k1_musig.h        — MuSig2 (threshold signing)
#
# MWEB (MimbleWimble Extension Blocks):
#   Pedersen commitments + Bulletproofs → secp256k1/zk.hpp
#   Enable: -DSECP256K1_BUILD_BCH=OFF (MWEB module TBD, uses zk.cpp)
# ============================================================================

cmake_minimum_required(VERSION 3.18)
project(secp256k1_litecoin_shim LANGUAGES CXX)

# Litecoin shim = Bitcoin Core shim (identical API surface)
set(LTC_SHIM_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../libsecp256k1_shim")

add_library(secp256k1_litecoin_shim ALIAS secp256k1_shim)

message(STATUS "Litecoin secp256k1 backend: UltrafastSecp256k1 (via libsecp256k1_shim)")
message(STATUS "  Taproot: ON  |  Schnorr: BIP-340  |  MWEB Pedersen: via zk.hpp")
