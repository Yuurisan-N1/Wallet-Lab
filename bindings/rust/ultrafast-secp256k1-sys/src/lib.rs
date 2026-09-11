//! Raw FFI bindings to the UltrafastSecp256k1 C API.
//!
//! This crate provides unsafe bindings. Use the `ultrafast-secp256k1` crate
//! for a safe Rust interface.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int};

/// Opaque BIP-32 extended key (78 bytes data + 1 byte is_private).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct secp256k1_bip32_key {
    pub data: [u8; 78],
    pub is_private: u8,
}

extern "C" {
    // ── Version & Lifecycle ──────────────────────────────────────────────
    pub fn secp256k1_version() -> *const c_char;
    pub fn secp256k1_init() -> c_int;

    // ── Key Operations ───────────────────────────────────────────────────
    pub fn secp256k1_ec_pubkey_create(privkey: *const u8, pubkey_out: *mut u8) -> c_int;
    pub fn secp256k1_ec_pubkey_create_uncompressed(privkey: *const u8, pubkey_out: *mut u8) -> c_int;
    pub fn secp256k1_ec_pubkey_parse(input: *const u8, input_len: usize, pubkey_out: *mut u8) -> c_int;
    pub fn secp256k1_ec_seckey_verify(privkey: *const u8) -> c_int;
    pub fn secp256k1_ec_privkey_negate(privkey: *mut u8) -> c_int;
    pub fn secp256k1_ec_privkey_tweak_add(privkey: *mut u8, tweak: *const u8) -> c_int;
    pub fn secp256k1_ec_privkey_tweak_mul(privkey: *mut u8, tweak: *const u8) -> c_int;

    // ── ECDSA ────────────────────────────────────────────────────────────
    pub fn secp256k1_ecdsa_sign(msg_hash: *const u8, privkey: *const u8, sig_out: *mut u8) -> c_int;
    pub fn secp256k1_ecdsa_verify(msg_hash: *const u8, sig: *const u8, pubkey: *const u8) -> c_int;
    pub fn secp256k1_ecdsa_signature_serialize_der(sig: *const u8, der_out: *mut u8, der_len: *mut usize) -> c_int;

    // ── Recovery ─────────────────────────────────────────────────────────
    pub fn secp256k1_ecdsa_sign_recoverable(msg_hash: *const u8, privkey: *const u8, sig_out: *mut u8, recid_out: *mut c_int) -> c_int;
    pub fn secp256k1_ecdsa_recover(msg_hash: *const u8, sig: *const u8, recid: c_int, pubkey_out: *mut u8) -> c_int;

    // ── Schnorr ──────────────────────────────────────────────────────────
    pub fn secp256k1_schnorr_sign(msg: *const u8, privkey: *const u8, aux_rand: *const u8, sig_out: *mut u8) -> c_int;
    pub fn secp256k1_schnorr_verify(msg: *const u8, sig: *const u8, pubkey_x: *const u8) -> c_int;
    pub fn secp256k1_schnorr_pubkey(privkey: *const u8, pubkey_x_out: *mut u8) -> c_int;

    // ── ECDH ─────────────────────────────────────────────────────────────
    pub fn secp256k1_ecdh(privkey: *const u8, pubkey: *const u8, secret_out: *mut u8) -> c_int;
    pub fn secp256k1_ecdh_xonly(privkey: *const u8, pubkey: *const u8, secret_out: *mut u8) -> c_int;
    pub fn secp256k1_ecdh_raw(privkey: *const u8, pubkey: *const u8, secret_out: *mut u8) -> c_int;

    // ── Hashing ──────────────────────────────────────────────────────────
    pub fn secp256k1_sha256(data: *const u8, data_len: usize, digest_out: *mut u8);
    pub fn secp256k1_hash160(data: *const u8, data_len: usize, digest_out: *mut u8);
    pub fn secp256k1_tagged_hash(tag: *const c_char, data: *const u8, data_len: usize, digest_out: *mut u8);

    // ── Addresses ────────────────────────────────────────────────────────
    pub fn secp256k1_address_p2pkh(pubkey: *const u8, network: c_int, addr_out: *mut c_char, addr_len: *mut usize) -> c_int;
    pub fn secp256k1_address_p2wpkh(pubkey: *const u8, network: c_int, addr_out: *mut c_char, addr_len: *mut usize) -> c_int;
    pub fn secp256k1_address_p2tr(internal_key_x: *const u8, network: c_int, addr_out: *mut c_char, addr_len: *mut usize) -> c_int;

    // ── WIF ──────────────────────────────────────────────────────────────
    pub fn secp256k1_wif_encode(privkey: *const u8, compressed: c_int, network: c_int, wif_out: *mut c_char, wif_len: *mut usize) -> c_int;
    pub fn secp256k1_wif_decode(wif: *const c_char, privkey_out: *mut u8, compressed_out: *mut c_int, network_out: *mut c_int) -> c_int;

    // ── BIP-32 ───────────────────────────────────────────────────────────
    pub fn secp256k1_bip32_master_key(seed: *const u8, seed_len: usize, key_out: *mut secp256k1_bip32_key) -> c_int;
    pub fn secp256k1_bip32_derive_child(parent: *const secp256k1_bip32_key, index: u32, child_out: *mut secp256k1_bip32_key) -> c_int;
    pub fn secp256k1_bip32_derive_path(master: *const secp256k1_bip32_key, path: *const c_char, key_out: *mut secp256k1_bip32_key) -> c_int;
    pub fn secp256k1_bip32_get_privkey(key: *const secp256k1_bip32_key, privkey_out: *mut u8) -> c_int;
    pub fn secp256k1_bip32_get_pubkey(key: *const secp256k1_bip32_key, pubkey_out: *mut u8) -> c_int;

    // ── Taproot ──────────────────────────────────────────────────────────
    pub fn secp256k1_taproot_output_key(internal_key_x: *const u8, merkle_root: *const u8, output_key_x_out: *mut u8, parity_out: *mut c_int) -> c_int;
    pub fn secp256k1_taproot_tweak_privkey(privkey: *const u8, merkle_root: *const u8, tweaked_privkey_out: *mut u8) -> c_int;
    pub fn secp256k1_taproot_verify_commitment(output_key_x: *const u8, output_key_parity: c_int, internal_key_x: *const u8, merkle_root: *const u8, merkle_root_len: usize) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_version() {
        unsafe {
            let v = secp256k1_version();
            let s = CStr::from_ptr(v).to_str().unwrap();
            assert!(s.starts_with("1."));
        }
    }
}
