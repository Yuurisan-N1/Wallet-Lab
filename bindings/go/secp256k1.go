//go:build ultrafast_legacy
// +build ultrafast_legacy

// Package secp256k1 provides Go bindings for the UltrafastSecp256k1 C library.
//
// High-performance secp256k1 elliptic curve cryptography: key operations,
// ECDSA, Schnorr (BIP-340), ECDH, recovery, hashing, Bitcoin addresses,
// WIF, BIP-32, and Taproot.
//
// Build requirements: the ultrafast_secp256k1 shared library must be
// installed or pointed to via CGO_LDFLAGS / LD_LIBRARY_PATH.
package secp256k1

/*
#cgo LDFLAGS: -lultrafast_secp256k1
#cgo CFLAGS: -I${SRCDIR}/../c_api

#include "ultrafast_secp256k1.h"
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

// Network selects mainnet or testnet address encoding.
type Network int

const (
	Mainnet Network = C.SECP256K1_NETWORK_MAINNET
	Testnet Network = C.SECP256K1_NETWORK_TESTNET
)

// Common errors.
var (
	ErrInvalidPrivateKey = errors.New("secp256k1: invalid private key")
	ErrInvalidPublicKey  = errors.New("secp256k1: invalid public key")
	ErrSigningFailed     = errors.New("secp256k1: signing failed")
	ErrVerifyFailed      = errors.New("secp256k1: verification returned invalid")
	ErrRecoveryFailed    = errors.New("secp256k1: recovery failed")
	ErrECDHFailed        = errors.New("secp256k1: ECDH computation failed")
	ErrTweakFailed       = errors.New("secp256k1: tweak operation failed")
	ErrAddressFailed     = errors.New("secp256k1: address generation failed")
	ErrWIFFailed         = errors.New("secp256k1: WIF encode/decode failed")
	ErrBIP32Failed       = errors.New("secp256k1: BIP-32 operation failed")
	ErrTaprootFailed     = errors.New("secp256k1: taproot operation failed")
	ErrDERFailed         = errors.New("secp256k1: DER serialization failed")
	ErrInitFailed        = errors.New("secp256k1: library initialization failed")
)

// Init initialises the library (selftest). Must be called once before use.
func Init() error {
	if rc := C.secp256k1_init(); rc != 0 {
		return ErrInitFailed
	}
	return nil
}

// Version returns the library version string.
func Version() string {
	return C.GoString(C.secp256k1_version())
}

// ── Key Operations ───────────────────────────────────────────────────────────

// PubkeyCreate computes a compressed (33-byte) public key from a 32-byte private key.
func PubkeyCreate(privkey [32]byte) ([33]byte, error) {
	var out [33]byte
	rc := C.secp256k1_ec_pubkey_create(
		(*C.uint8_t)(unsafe.Pointer(&privkey[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if rc != 0 {
		return out, ErrInvalidPrivateKey
	}
	return out, nil
}

// PubkeyCreateUncompressed computes an uncompressed (65-byte) public key.
func PubkeyCreateUncompressed(privkey [32]byte) ([65]byte, error) {
	var out [65]byte
	rc := C.secp256k1_ec_pubkey_create_uncompressed(
		(*C.uint8_t)(unsafe.Pointer(&privkey[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if rc != 0 {
		return out, ErrInvalidPrivateKey
	}
	return out, nil
}

// PubkeyParse parses a compressed (33) or uncompressed (65) public key.
// Returns compressed form.
func PubkeyParse(input []byte) ([33]byte, error) {
	if len(input) != 33 && len(input) != 65 {
		return [33]byte{}, fmt.Errorf("secp256k1: pubkey must be 33 or 65 bytes, got %d", len(input))
	}
	var out [33]byte
	rc := C.secp256k1_ec_pubkey_parse(
		(*C.uint8_t)(unsafe.Pointer(&input[0])),
		C.size_t(len(input)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if rc != 0 {
		return out, ErrInvalidPublicKey
	}
	return out, nil
}

// SeckeyVerify checks whether a private key is valid.
func SeckeyVerify(privkey [32]byte) bool {
	rc := C.secp256k1_ec_seckey_verify((*C.uint8_t)(unsafe.Pointer(&privkey[0])))
	return rc == 1
}

// PrivkeyNegate negates a private key (mod n).
func PrivkeyNegate(privkey [32]byte) [32]byte {
	out := privkey
	C.secp256k1_ec_privkey_negate((*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out
}

// PrivkeyTweakAdd adds a tweak to a private key: key = (key + tweak) mod n.
func PrivkeyTweakAdd(privkey, tweak [32]byte) ([32]byte, error) {
	out := privkey
	rc := C.secp256k1_ec_privkey_tweak_add(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		(*C.uint8_t)(unsafe.Pointer(&tweak[0])),
	)
	if rc != 0 {
		return out, ErrTweakFailed
	}
	return out, nil
}

// PrivkeyTweakMul multiplies a private key by a tweak: key = (key * tweak) mod n.
func PrivkeyTweakMul(privkey, tweak [32]byte) ([32]byte, error) {
	out := privkey
	rc := C.secp256k1_ec_privkey_tweak_mul(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		(*C.uint8_t)(unsafe.Pointer(&tweak[0])),
	)
	if rc != 0 {
		return out, ErrTweakFailed
	}
	return out, nil
}

// ── ECDSA ────────────────────────────────────────────────────────────────────

// EcdsaSign signs a 32-byte hash with ECDSA (RFC 6979). Returns 64-byte compact sig.
func EcdsaSign(msgHash, privkey [32]byte) ([64]byte, error) {
	var sig [64]byte
	rc := C.secp256k1_ecdsa_sign(
		(*C.uint8_t)(unsafe.Pointer(&msgHash[0])),
		(*C.uint8_t)(unsafe.Pointer(&privkey[0])),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
	)
	if rc != 0 {
		return sig, ErrSigningFailed
	}
	return sig, nil
}

// EcdsaVerify verifies an ECDSA signature.
func EcdsaVerify(msgHash [32]byte, sig [64]byte, pubkey [33]byte) bool {
	rc := C.secp256k1_ecdsa_verify(
		(*C.uint8_t)(unsafe.Pointer(&msgHash[0])),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		(*C.uint8_t)(unsafe.Pointer(&pubkey[0])),
	)
	return rc == 1
}

// EcdsaSerializeDER encodes a compact 64-byte sig into DER format.
func EcdsaSerializeDER(sig [64]byte) ([]byte, error) {
	var der [72]byte
	derLen := C.size_t(72)
	rc := C.secp256k1_ecdsa_signature_serialize_der(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		(*C.uint8_t)(unsafe.Pointer(&der[0])),
		&derLen,
	)
	if rc != 0 {
		return nil, ErrDERFailed
	}
	return append([]byte{}, der[:derLen]...), nil
}

// ── Recovery ─────────────────────────────────────────────────────────────────

// EcdsaSignRecoverable signs with a recovery id.
func EcdsaSignRecoverable(msgHash, privkey [32]byte) (sig [64]byte, recid int, err error) {
	var cRecid C.int
	rc := C.secp256k1_ecdsa_sign_recoverable(
		(*C.uint8_t)(unsafe.Pointer(&msgHash[0])),
		(*C.uint8_t)(unsafe.Pointer(&privkey[0])),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		&cRecid,
	)
	if rc != 0 {
		return sig, 0, ErrSigningFailed
	}
	return sig, int(cRecid), nil
}

// EcdsaRecover recovers a compressed public key from a recoverable signature.
func EcdsaRecover(msgHash [32]byte, sig [64]byte, recid int) ([33]byte, error) {
	var pubkey [33]byte
	rc := C.secp256k1_ecdsa_recover(
		(*C.uint8_t)(unsafe.Pointer(&msgHash[0])),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		C.int(recid),
		(*C.uint8_t)(unsafe.Pointer(&pubkey[0])),
	)
	if rc != 0 {
		return pubkey, ErrRecoveryFailed
	}
	return pubkey, nil
}

// ── Schnorr (BIP-340) ───────────────────────────────────────────────────────

// SchnorrSign creates a BIP-340 Schnorr signature (64 bytes).
func SchnorrSign(msg, privkey, auxRand [32]byte) ([64]byte, error) {
	var sig [64]byte
	rc := C.secp256k1_schnorr_sign(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
		(*C.uint8_t)(unsafe.Pointer(&privkey[0])),
		(*C.uint8_t)(unsafe.Pointer(&auxRand[0])),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
	)
	if rc != 0 {
		return sig, ErrSigningFailed
	}
	return sig, nil
}

// SchnorrVerify verifies a BIP-340 Schnorr signature.
func SchnorrVerify(msg [32]byte, sig [64]byte, pubkeyX [32]byte) bool {
	rc := C.secp256k1_schnorr_verify(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		(*C.uint8_t)(unsafe.Pointer(&pubkeyX[0])),
	)
	return rc == 1
}

// SchnorrPubkey returns the 32-byte x-only public key for Schnorr.
func SchnorrPubkey(privkey [32]byte) ([32]byte, error) {
	var out [32]byte
	rc := C.secp256k1_schnorr_pubkey(
		(*C.uint8_t)(unsafe.Pointer(&privkey[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if rc != 0 {
		return out, ErrInvalidPrivateKey
	}
	return out, nil
}

// ── ECDH ─────────────────────────────────────────────────────────────────────

// ECDH computes a shared secret: SHA256(compressed_shared_point).
func ECDH(privkey [32]byte, pubkey [33]byte) ([32]byte, error) {
	var out [32]byte
	rc := C.secp256k1_ecdh(
		(*C.uint8_t)(unsafe.Pointer(&privkey[0])),
		(*C.uint8_t)(unsafe.Pointer(&pubkey[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if rc != 0 {
		return out, ErrECDHFailed
	}
	return out, nil
}

// ECDHXonly computes a shared secret from x-coordinate only.
func ECDHXonly(privkey [32]byte, pubkey [33]byte) ([32]byte, error) {
	var out [32]byte
	rc := C.secp256k1_ecdh_xonly(
		(*C.uint8_t)(unsafe.Pointer(&privkey[0])),
		(*C.uint8_t)(unsafe.Pointer(&pubkey[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if rc != 0 {
		return out, ErrECDHFailed
	}
	return out, nil
}

// ECDHRaw returns the raw x-coordinate of the shared point.
func ECDHRaw(privkey [32]byte, pubkey [33]byte) ([32]byte, error) {
	var out [32]byte
	rc := C.secp256k1_ecdh_raw(
		(*C.uint8_t)(unsafe.Pointer(&privkey[0])),
		(*C.uint8_t)(unsafe.Pointer(&pubkey[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if rc != 0 {
		return out, ErrECDHFailed
	}
	return out, nil
}

// ── Hashing ──────────────────────────────────────────────────────────────────

// SHA256 computes a SHA-256 digest.
func SHA256(data []byte) [32]byte {
	var out [32]byte
	var p *C.uint8_t
	if len(data) > 0 {
		p = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	C.secp256k1_sha256(p, C.size_t(len(data)), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out
}

// Hash160 computes RIPEMD160(SHA256(data)).
func Hash160(data []byte) [20]byte {
	var out [20]byte
	var p *C.uint8_t
	if len(data) > 0 {
		p = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	C.secp256k1_hash160(p, C.size_t(len(data)), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out
}

// TaggedHash computes BIP-340 tagged hash: SHA256(SHA256(tag)||SHA256(tag)||data).
func TaggedHash(tag string, data []byte) [32]byte {
	var out [32]byte
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))
	var p *C.uint8_t
	if len(data) > 0 {
		p = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	C.secp256k1_tagged_hash(cTag, p, C.size_t(len(data)), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out
}

// ── Addresses ────────────────────────────────────────────────────────────────

func getAddress(fn func(buf *C.char, bufLen *C.size_t) C.int) (string, error) {
	var buf [128]C.char
	bufLen := C.size_t(128)
	rc := fn(&buf[0], &bufLen)
	if rc != 0 {
		return "", ErrAddressFailed
	}
	return C.GoStringN(&buf[0], C.int(bufLen)), nil
}

// AddressP2PKH generates a P2PKH address from a compressed public key.
func AddressP2PKH(pubkey [33]byte, net Network) (string, error) {
	return getAddress(func(buf *C.char, bufLen *C.size_t) C.int {
		return C.secp256k1_address_p2pkh(
			(*C.uint8_t)(unsafe.Pointer(&pubkey[0])),
			C.int(net), buf, bufLen,
		)
	})
}

// AddressP2WPKH generates a P2WPKH (SegWit v0) address.
func AddressP2WPKH(pubkey [33]byte, net Network) (string, error) {
	return getAddress(func(buf *C.char, bufLen *C.size_t) C.int {
		return C.secp256k1_address_p2wpkh(
			(*C.uint8_t)(unsafe.Pointer(&pubkey[0])),
			C.int(net), buf, bufLen,
		)
	})
}

// AddressP2TR generates a P2TR (Taproot) address from an x-only key.
func AddressP2TR(internalKeyX [32]byte, net Network) (string, error) {
	return getAddress(func(buf *C.char, bufLen *C.size_t) C.int {
		return C.secp256k1_address_p2tr(
			(*C.uint8_t)(unsafe.Pointer(&internalKeyX[0])),
			C.int(net), buf, bufLen,
		)
	})
}

// ── WIF ──────────────────────────────────────────────────────────────────────

// WIFEncode encodes a private key as WIF.
func WIFEncode(privkey [32]byte, compressed bool, net Network) (string, error) {
	comp := C.int(0)
	if compressed {
		comp = 1
	}
	return getAddress(func(buf *C.char, bufLen *C.size_t) C.int {
		return C.secp256k1_wif_encode(
			(*C.uint8_t)(unsafe.Pointer(&privkey[0])),
			comp, C.int(net), buf, bufLen,
		)
	})
}

// WIFDecodeResult holds the decoded WIF data.
type WIFDecodeResult struct {
	Privkey    [32]byte
	Compressed bool
	Network    Network
}

// WIFDecode decodes a WIF string.
func WIFDecode(wif string) (WIFDecodeResult, error) {
	cWIF := C.CString(wif)
	defer C.free(unsafe.Pointer(cWIF))
	var result WIFDecodeResult
	var comp, net C.int
	rc := C.secp256k1_wif_decode(
		cWIF,
		(*C.uint8_t)(unsafe.Pointer(&result.Privkey[0])),
		&comp, &net,
	)
	if rc != 0 {
		return result, ErrWIFFailed
	}
	result.Compressed = comp == 1
	result.Network = Network(net)
	return result, nil
}

// ── BIP-32 ───────────────────────────────────────────────────────────────────

// BIP32Key is an opaque BIP-32 extended key (79 bytes: 78 data + 1 flag).
type BIP32Key [79]byte

// BIP32MasterKey creates a master key from seed (16-64 bytes).
func BIP32MasterKey(seed []byte) (BIP32Key, error) {
	if len(seed) < 16 || len(seed) > 64 {
		return BIP32Key{}, fmt.Errorf("secp256k1: seed must be 16-64 bytes, got %d", len(seed))
	}
	var key BIP32Key
	rc := C.secp256k1_bip32_master_key(
		(*C.uint8_t)(unsafe.Pointer(&seed[0])),
		C.size_t(len(seed)),
		(*C.secp256k1_bip32_key)(unsafe.Pointer(&key[0])),
	)
	if rc != 0 {
		return key, ErrBIP32Failed
	}
	return key, nil
}

// BIP32DeriveChild derives a child key by index.
func BIP32DeriveChild(parent BIP32Key, index uint32) (BIP32Key, error) {
	var child BIP32Key
	rc := C.secp256k1_bip32_derive_child(
		(*C.secp256k1_bip32_key)(unsafe.Pointer(&parent[0])),
		C.uint32_t(index),
		(*C.secp256k1_bip32_key)(unsafe.Pointer(&child[0])),
	)
	if rc != 0 {
		return child, ErrBIP32Failed
	}
	return child, nil
}

// BIP32DerivePath derives from a path string, e.g. "m/44'/0'/0'/0/0".
func BIP32DerivePath(master BIP32Key, path string) (BIP32Key, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var key BIP32Key
	rc := C.secp256k1_bip32_derive_path(
		(*C.secp256k1_bip32_key)(unsafe.Pointer(&master[0])),
		cPath,
		(*C.secp256k1_bip32_key)(unsafe.Pointer(&key[0])),
	)
	if rc != 0 {
		return key, ErrBIP32Failed
	}
	return key, nil
}

// BIP32GetPrivkey extracts the 32-byte private key from an extended key.
func BIP32GetPrivkey(key BIP32Key) ([32]byte, error) {
	var privkey [32]byte
	rc := C.secp256k1_bip32_get_privkey(
		(*C.secp256k1_bip32_key)(unsafe.Pointer(&key[0])),
		(*C.uint8_t)(unsafe.Pointer(&privkey[0])),
	)
	if rc != 0 {
		return privkey, ErrBIP32Failed
	}
	return privkey, nil
}

// BIP32GetPubkey extracts the compressed 33-byte public key from an extended key.
func BIP32GetPubkey(key BIP32Key) ([33]byte, error) {
	var pubkey [33]byte
	rc := C.secp256k1_bip32_get_pubkey(
		(*C.secp256k1_bip32_key)(unsafe.Pointer(&key[0])),
		(*C.uint8_t)(unsafe.Pointer(&pubkey[0])),
	)
	if rc != 0 {
		return pubkey, ErrBIP32Failed
	}
	return pubkey, nil
}

// ── Taproot ──────────────────────────────────────────────────────────────────

// TaprootOutputKey derives the output key from an internal key.
// merkleRoot can be nil for key-path only.
func TaprootOutputKey(internalKeyX [32]byte, merkleRoot *[32]byte) (outputKeyX [32]byte, parity int, err error) {
	var mr *C.uint8_t
	if merkleRoot != nil {
		mr = (*C.uint8_t)(unsafe.Pointer(&merkleRoot[0]))
	}
	var cParity C.int
	rc := C.secp256k1_taproot_output_key(
		(*C.uint8_t)(unsafe.Pointer(&internalKeyX[0])),
		mr,
		(*C.uint8_t)(unsafe.Pointer(&outputKeyX[0])),
		&cParity,
	)
	if rc != 0 {
		return outputKeyX, 0, ErrTaprootFailed
	}
	return outputKeyX, int(cParity), nil
}

// TaprootTweakPrivkey tweaks a private key for Taproot key-path spending.
func TaprootTweakPrivkey(privkey [32]byte, merkleRoot *[32]byte) ([32]byte, error) {
	var mr *C.uint8_t
	if merkleRoot != nil {
		mr = (*C.uint8_t)(unsafe.Pointer(&merkleRoot[0]))
	}
	var out [32]byte
	rc := C.secp256k1_taproot_tweak_privkey(
		(*C.uint8_t)(unsafe.Pointer(&privkey[0])),
		mr,
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if rc != 0 {
		return out, ErrTaprootFailed
	}
	return out, nil
}

// TaprootVerifyCommitment verifies a Taproot commitment.
func TaprootVerifyCommitment(outputKeyX [32]byte, outputKeyParity int, internalKeyX [32]byte, merkleRoot []byte) bool {
	var mr *C.uint8_t
	mrLen := C.size_t(len(merkleRoot))
	if len(merkleRoot) > 0 {
		mr = (*C.uint8_t)(unsafe.Pointer(&merkleRoot[0]))
	}
	rc := C.secp256k1_taproot_verify_commitment(
		(*C.uint8_t)(unsafe.Pointer(&outputKeyX[0])),
		C.int(outputKeyParity),
		(*C.uint8_t)(unsafe.Pointer(&internalKeyX[0])),
		mr,
		mrLen,
	)
	return rc == 1
}
