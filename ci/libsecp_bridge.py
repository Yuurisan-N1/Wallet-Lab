#!/usr/bin/env python3
"""
libsecp_bridge.py — ctypes bridge wrapping bitcoin-core/secp256k1
as a drop-in substitute for _ufsecp.py, enabling CAAS audit scripts
to run against libsecp256k1 instead of UltrafastSecp256k1.

Usage:
    python3 ci/libsecp_bridge.py --self-test
    LIBSECP_BRIDGE=1 LIBSECP_PATH=/tmp/libsecp-build/lib/libsecp256k1.so.6 \
        python3 ci/invalid_input_grammar.py --lib __bridge__ -o out.json
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
import hashlib
import struct
from pathlib import Path
from typing import Optional

# ── Locate the library ─────────────────────────────────────────────────────

def _find_libsecp(hint: Optional[str] = None) -> str:
    candidates = []
    if hint and hint != '__bridge__':
        candidates.append(hint)
    env = os.environ.get('LIBSECP_PATH', '')
    if env:
        candidates.append(env)
    # Common build paths
    for p in [
        '/tmp/libsecp-build/lib/libsecp256k1.so.6',
        '/tmp/libsecp-build/lib/libsecp256k1.so',
        '/usr/lib/x86_64-linux-gnu/libsecp256k1.so.0',
        '/usr/local/lib/libsecp256k1.so',
    ]:
        candidates.append(p)
    found = ctypes.util.find_library('secp256k1')
    if found:
        candidates.append(found)
    for c in candidates:
        if Path(c).exists():
            return c
    raise FileNotFoundError(
        "Cannot locate libsecp256k1.so. "
        "Set LIBSECP_PATH=/path/to/libsecp256k1.so or pass --lib explicitly."
    )


# ── ctypes struct definitions ───────────────────────────────────────────────

class _Ctx(ctypes.Structure):
    pass

class _Pubkey(ctypes.Structure):
    _fields_ = [('data', ctypes.c_uint8 * 64)]

class _Sig(ctypes.Structure):
    _fields_ = [('data', ctypes.c_uint8 * 64)]

class _XonlyPubkey(ctypes.Structure):
    _fields_ = [('data', ctypes.c_uint8 * 64)]

class _Keypair(ctypes.Structure):
    _fields_ = [('data', ctypes.c_uint8 * 96)]


# libsecp256k1 v0.5+ flag layout (FLAGS_TYPE_CONTEXT | FLAGS_BIT_*)
_FLAGS_TYPE_CONTEXT        = 1
_FLAGS_BIT_CONTEXT_VERIFY  = (1 << 8)   # 256
_FLAGS_BIT_CONTEXT_SIGN    = (1 << 9)   # 512
_FLAGS_BIT_COMPRESSION     = (1 << 8)   # 256
_FLAGS_TYPE_COMPRESSION    = (1 << 1)   # 2

CONTEXT_NONE   = _FLAGS_TYPE_CONTEXT
CONTEXT_VERIFY = _FLAGS_TYPE_CONTEXT | _FLAGS_BIT_CONTEXT_VERIFY   # 257
CONTEXT_SIGN   = _FLAGS_TYPE_CONTEXT | _FLAGS_BIT_CONTEXT_SIGN     # 513
_EC_COMPRESSED = _FLAGS_TYPE_COMPRESSION | _FLAGS_BIT_COMPRESSION  # 258


# ── UfSecp-compatible Python wrapper ───────────────────────────────────────

class LibsecpBridge:
    """
    Wraps bitcoin-core/secp256k1 C API with a UfSecp-compatible interface.
    Covers the subset of operations exercised by the CAAS audit scripts.
    """

    def __init__(self, lib_path: str):
        self._lib = ctypes.CDLL(lib_path)
        self._setup_prototypes()
        self._ctx = self._lib.secp256k1_context_create(CONTEXT_SIGN | CONTEXT_VERIFY)  # 769
        assert self._ctx, "secp256k1_context_create failed"

    def _setup_prototypes(self):
        L = self._lib

        L.secp256k1_context_create.restype = ctypes.c_void_p
        L.secp256k1_context_create.argtypes = [ctypes.c_uint]

        L.secp256k1_context_destroy.restype = None
        L.secp256k1_context_destroy.argtypes = [ctypes.c_void_p]

        L.secp256k1_context_randomize.restype = ctypes.c_int
        L.secp256k1_context_randomize.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

        L.secp256k1_ec_pubkey_create.restype = ctypes.c_int
        L.secp256k1_ec_pubkey_create.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_Pubkey), ctypes.c_char_p]

        L.secp256k1_ec_pubkey_parse.restype = ctypes.c_int
        L.secp256k1_ec_pubkey_parse.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_Pubkey), ctypes.c_char_p, ctypes.c_size_t]

        L.secp256k1_ec_pubkey_serialize.restype = ctypes.c_int
        L.secp256k1_ec_pubkey_serialize.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(_Pubkey), ctypes.c_uint]

        L.secp256k1_ecdsa_sign.restype = ctypes.c_int
        L.secp256k1_ecdsa_sign.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_Sig), ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]

        L.secp256k1_ecdsa_verify.restype = ctypes.c_int
        L.secp256k1_ecdsa_verify.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_Sig), ctypes.c_char_p,
            ctypes.POINTER(_Pubkey)]

        L.secp256k1_ecdsa_signature_serialize_compact.restype = ctypes.c_int
        L.secp256k1_ecdsa_signature_serialize_compact.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(_Sig)]

        L.secp256k1_ecdsa_signature_parse_compact.restype = ctypes.c_int
        L.secp256k1_ecdsa_signature_parse_compact.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_Sig), ctypes.c_char_p]

        L.secp256k1_ecdsa_signature_normalize.restype = ctypes.c_int
        L.secp256k1_ecdsa_signature_normalize.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_Sig), ctypes.POINTER(_Sig)]

        L.secp256k1_ec_seckey_verify.restype = ctypes.c_int
        L.secp256k1_ec_seckey_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    # ── Public API (UfSecp-compatible) ────────────────────────────────────

    def ec_seckey_verify(self, sk32: bytes) -> bool:
        return bool(self._lib.secp256k1_ec_seckey_verify(self._ctx, sk32))

    def ec_pubkey_create(self, sk32: bytes) -> Optional[bytes]:
        pk = _Pubkey()
        if not self._lib.secp256k1_ec_pubkey_create(self._ctx, ctypes.byref(pk), sk32):
            return None
        out = ctypes.create_string_buffer(33)
        outlen = ctypes.c_size_t(33)
        self._lib.secp256k1_ec_pubkey_serialize(
            self._ctx, out, ctypes.byref(outlen), ctypes.byref(pk), _EC_COMPRESSED)
        return bytes(out[:outlen.value])

    def ecdsa_sign(self, msg32: bytes, sk32: bytes) -> Optional[bytes]:
        sig = _Sig()
        if not self._lib.secp256k1_ecdsa_sign(
                self._ctx, ctypes.byref(sig), msg32, sk32, None, None):
            return None
        compact = ctypes.create_string_buffer(64)
        self._lib.secp256k1_ecdsa_signature_serialize_compact(
            self._ctx, compact, ctypes.byref(sig))
        return bytes(compact)

    def ecdsa_verify(self, msg32: bytes, sig64: bytes, pk33: bytes) -> bool:
        pk = _Pubkey()
        if not self._lib.secp256k1_ec_pubkey_parse(self._ctx, ctypes.byref(pk), pk33, len(pk33)):
            return False
        sig = _Sig()
        if not self._lib.secp256k1_ecdsa_signature_parse_compact(self._ctx, ctypes.byref(sig), sig64):
            return False
        # Normalize to low-S
        self._lib.secp256k1_ecdsa_signature_normalize(
            self._ctx, ctypes.byref(sig), ctypes.byref(sig))
        return bool(self._lib.secp256k1_ecdsa_verify(
            self._ctx, ctypes.byref(sig), msg32, ctypes.byref(pk)))

    def ec_pubkey_parse(self, compressed: bytes) -> Optional[bytes]:
        """Parse compressed pubkey, return compressed bytes."""
        pk = _Pubkey()
        if not self._lib.secp256k1_ec_pubkey_parse(
                self._ctx, ctypes.byref(pk), compressed, len(compressed)):
            return None
        out = ctypes.create_string_buffer(33)
        outlen = ctypes.c_size_t(33)
        self._lib.secp256k1_ec_pubkey_serialize(
            self._ctx, out, ctypes.byref(outlen), ctypes.byref(pk), _EC_COMPRESSED)
        return bytes(out[:outlen.value])

    @property
    def version(self) -> str:
        return "libsecp256k1 (bitcoin-core)"

    def selftest(self) -> bool:
        """Quick sanity check: sign and verify with known key."""
        import os
        sk = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
        msg = hashlib.sha256(b'libsecp_bridge_selftest').digest()
        sig = self.ecdsa_sign(msg, sk)
        if sig is None:
            return False
        pk = self.ec_pubkey_create(sk)
        if pk is None:
            return False
        return self.ecdsa_verify(msg, sig, pk)

    def __del__(self):
        try:
            self._lib.secp256k1_context_destroy(self._ctx)
        except Exception:
            pass


# ── find_lib shim for compatibility with _ufsecp.py interface ──────────────

def find_lib(hint: Optional[str] = None) -> str:
    return _find_libsecp(hint)


# ── Self-test ───────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test', action='store_true')
    p.add_argument('--lib', default=None)
    args = p.parse_args()

    lib_path = _find_libsecp(args.lib)
    print(f"Using: {lib_path}")

    bridge = LibsecpBridge(lib_path)
    ok = bridge.selftest()
    print(f"Self-test: {'PASS' if ok else 'FAIL'}")

    if args.self_test:
        # Quick coverage of key operations
        import secrets
        sk = secrets.token_bytes(32)
        # Ensure sk < n (simplified)
        sk = bytes([sk[0] % 0x80 or 0x01]) + sk[1:]

        pk = bridge.ec_pubkey_create(sk)
        print(f"  pubkey_create: {'OK' if pk else 'FAIL'}")

        msg = hashlib.sha256(b'test').digest()
        sig = bridge.ecdsa_sign(msg, sk)
        print(f"  ecdsa_sign: {'OK' if sig else 'FAIL'}")

        valid = bridge.ecdsa_verify(msg, sig, pk) if sig else False
        print(f"  ecdsa_verify: {'OK' if valid else 'FAIL'}")

        wrong_msg = hashlib.sha256(b'wrong').digest()
        invalid = bridge.ecdsa_verify(wrong_msg, sig, pk) if sig else True
        print(f"  wrong_msg rejects: {'OK' if not invalid else 'FAIL'}")

        sk_verify = bridge.ec_seckey_verify(sk)
        print(f"  seckey_verify: {'OK' if sk_verify else 'FAIL'}")

        zero_sk = b'\x00' * 32
        zero_ok = bridge.ec_seckey_verify(zero_sk)
        print(f"  zero_sk rejects: {'OK' if not zero_ok else 'FAIL'}")

        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
