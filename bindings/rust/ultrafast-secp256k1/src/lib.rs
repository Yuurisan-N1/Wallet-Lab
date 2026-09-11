//! Safe Rust bindings for UltrafastSecp256k1.
//!
//! High-performance secp256k1 elliptic curve cryptography.
//!
//! # Example
//! ```no_run
//! use ultrafast_secp256k1::Secp256k1;
//!
//! let lib = Secp256k1::new().unwrap();
//!
//! let privkey = [0u8; 32];  // your private key
//! let pubkey = lib.ec_pubkey_create(&privkey).unwrap();
//!
//! let msg_hash = [0u8; 32];
//! let sig = lib.ecdsa_sign(&msg_hash, &privkey).unwrap();
//! assert!(lib.ecdsa_verify(&msg_hash, &sig, &pubkey));
//! ```

use std::ffi::{CStr, CString};
use std::fmt;
use std::sync::Once;

use ultrafast_secp256k1_sys as ffi;

// ── Error type ──────────────────────────────────────────────────────────────

/// Error type for secp256k1 operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Library selftest failed.
    InitFailed,
    /// Invalid private key (zero or >= curve order).
    InvalidSecretKey,
    /// Invalid public key format.
    InvalidPublicKey,
    /// Signing operation failed.
    SigningFailed,
    /// Verification failed (signature invalid).
    VerificationFailed,
    /// Recovery failed.
    RecoveryFailed,
    /// ECDH computation failed.
    EcdhFailed,
    /// Address generation failed.
    AddressFailed,
    /// WIF encode/decode failed.
    WifFailed,
    /// BIP-32 derivation failed.
    Bip32Failed,
    /// Taproot operation failed.
    TaprootFailed,
    /// DER serialization failed.
    SerializationFailed,
    /// Buffer too small.
    BufferTooSmall,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InitFailed => write!(f, "library selftest failed"),
            Error::InvalidSecretKey => write!(f, "invalid secret key"),
            Error::InvalidPublicKey => write!(f, "invalid public key"),
            Error::SigningFailed => write!(f, "signing failed"),
            Error::VerificationFailed => write!(f, "verification failed"),
            Error::RecoveryFailed => write!(f, "recovery failed"),
            Error::EcdhFailed => write!(f, "ECDH failed"),
            Error::AddressFailed => write!(f, "address generation failed"),
            Error::WifFailed => write!(f, "WIF encode/decode failed"),
            Error::Bip32Failed => write!(f, "BIP-32 derivation failed"),
            Error::TaprootFailed => write!(f, "taproot operation failed"),
            Error::SerializationFailed => write!(f, "serialization failed"),
            Error::BufferTooSmall => write!(f, "buffer too small"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

// ── Network ─────────────────────────────────────────────────────────────────

/// Bitcoin network selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Network {
    Mainnet = 0,
    Testnet = 1,
}

// ── Library handle ──────────────────────────────────────────────────────────

static INIT: Once = Once::new();
static mut INIT_RESULT: i32 = -1;

/// Main entry point for all secp256k1 operations.
///
/// Thread-safe. Library initialization (selftest) runs once on first `new()`.
pub struct Secp256k1 {
    _private: (),
}

impl Secp256k1 {
    /// Initialize the library. Runs selftest on first call.
    pub fn new() -> Result<Self> {
        INIT.call_once(|| {
            unsafe {
                INIT_RESULT = ffi::secp256k1_init();
            }
        });
        if unsafe { INIT_RESULT } != 0 {
            return Err(Error::InitFailed);
        }
        Ok(Secp256k1 { _private: () })
    }

    /// Return the native library version string.
    pub fn version(&self) -> &str {
        unsafe {
            let ptr = ffi::secp256k1_version();
            CStr::from_ptr(ptr).to_str().unwrap_or("unknown")
        }
    }

    // ── Key Operations ───────────────────────────────────────────────────

    /// Compute compressed public key (33 bytes) from private key (32 bytes).
    pub fn ec_pubkey_create(&self, privkey: &[u8; 32]) -> Result<[u8; 33]> {
        let mut pubkey = [0u8; 33];
        let rc = unsafe { ffi::secp256k1_ec_pubkey_create(privkey.as_ptr(), pubkey.as_mut_ptr()) };
        if rc != 0 { return Err(Error::InvalidSecretKey); }
        Ok(pubkey)
    }

    /// Compute uncompressed public key (65 bytes) from private key.
    pub fn ec_pubkey_create_uncompressed(&self, privkey: &[u8; 32]) -> Result<[u8; 65]> {
        let mut pubkey = [0u8; 65];
        let rc = unsafe { ffi::secp256k1_ec_pubkey_create_uncompressed(privkey.as_ptr(), pubkey.as_mut_ptr()) };
        if rc != 0 { return Err(Error::InvalidSecretKey); }
        Ok(pubkey)
    }

    /// Parse compressed (33) or uncompressed (65) public key. Returns compressed.
    pub fn ec_pubkey_parse(&self, input: &[u8]) -> Result<[u8; 33]> {
        let mut pubkey = [0u8; 33];
        let rc = unsafe { ffi::secp256k1_ec_pubkey_parse(input.as_ptr(), input.len(), pubkey.as_mut_ptr()) };
        if rc != 0 { return Err(Error::InvalidPublicKey); }
        Ok(pubkey)
    }

    /// Verify that a private key is valid.
    pub fn ec_seckey_verify(&self, privkey: &[u8; 32]) -> bool {
        unsafe { ffi::secp256k1_ec_seckey_verify(privkey.as_ptr()) == 1 }
    }

    /// Negate a private key (mod n).
    pub fn ec_privkey_negate(&self, privkey: &[u8; 32]) -> [u8; 32] {
        let mut result = *privkey;
        unsafe { ffi::secp256k1_ec_privkey_negate(result.as_mut_ptr()); }
        result
    }

    /// Add tweak to private key: (key + tweak) mod n.
    pub fn ec_privkey_tweak_add(&self, privkey: &[u8; 32], tweak: &[u8; 32]) -> Result<[u8; 32]> {
        let mut result = *privkey;
        let rc = unsafe { ffi::secp256k1_ec_privkey_tweak_add(result.as_mut_ptr(), tweak.as_ptr()) };
        if rc != 0 { return Err(Error::InvalidSecretKey); }
        Ok(result)
    }

    /// Multiply private key by tweak: (key * tweak) mod n.
    pub fn ec_privkey_tweak_mul(&self, privkey: &[u8; 32], tweak: &[u8; 32]) -> Result<[u8; 32]> {
        let mut result = *privkey;
        let rc = unsafe { ffi::secp256k1_ec_privkey_tweak_mul(result.as_mut_ptr(), tweak.as_ptr()) };
        if rc != 0 { return Err(Error::InvalidSecretKey); }
        Ok(result)
    }

    // ── ECDSA ────────────────────────────────────────────────────────────

    /// Sign a 32-byte message hash with ECDSA (RFC 6979).
    /// Returns 64-byte compact signature (R || S, low-S normalized).
    pub fn ecdsa_sign(&self, msg_hash: &[u8; 32], privkey: &[u8; 32]) -> Result<[u8; 64]> {
        let mut sig = [0u8; 64];
        let rc = unsafe { ffi::secp256k1_ecdsa_sign(msg_hash.as_ptr(), privkey.as_ptr(), sig.as_mut_ptr()) };
        if rc != 0 { return Err(Error::SigningFailed); }
        Ok(sig)
    }

    /// Verify an ECDSA compact signature.
    pub fn ecdsa_verify(&self, msg_hash: &[u8; 32], sig: &[u8; 64], pubkey: &[u8; 33]) -> bool {
        unsafe { ffi::secp256k1_ecdsa_verify(msg_hash.as_ptr(), sig.as_ptr(), pubkey.as_ptr()) == 1 }
    }

    /// Serialize compact signature to DER format.
    pub fn ecdsa_signature_serialize_der(&self, sig: &[u8; 64]) -> Result<Vec<u8>> {
        let mut der = [0u8; 72];
        let mut der_len: usize = 72;
        let rc = unsafe { ffi::secp256k1_ecdsa_signature_serialize_der(sig.as_ptr(), der.as_mut_ptr(), &mut der_len) };
        if rc != 0 { return Err(Error::SerializationFailed); }
        Ok(der[..der_len].to_vec())
    }

    // ── ECDSA Recovery ───────────────────────────────────────────────────

    /// Sign with recovery id. Returns (64-byte sig, recid).
    pub fn ecdsa_sign_recoverable(&self, msg_hash: &[u8; 32], privkey: &[u8; 32]) -> Result<([u8; 64], i32)> {
        let mut sig = [0u8; 64];
        let mut recid: i32 = 0;
        let rc = unsafe {
            ffi::secp256k1_ecdsa_sign_recoverable(
                msg_hash.as_ptr(), privkey.as_ptr(), sig.as_mut_ptr(),
                &mut recid as *mut i32 as *mut std::os::raw::c_int
            )
        };
        if rc != 0 { return Err(Error::SigningFailed); }
        Ok((sig, recid))
    }

    /// Recover compressed public key from recoverable signature.
    pub fn ecdsa_recover(&self, msg_hash: &[u8; 32], sig: &[u8; 64], recid: i32) -> Result<[u8; 33]> {
        let mut pubkey = [0u8; 33];
        let rc = unsafe { ffi::secp256k1_ecdsa_recover(msg_hash.as_ptr(), sig.as_ptr(), recid, pubkey.as_mut_ptr()) };
        if rc != 0 { return Err(Error::RecoveryFailed); }
        Ok(pubkey)
    }

    // ── Schnorr (BIP-340) ────────────────────────────────────────────────

    /// Create BIP-340 Schnorr signature. Returns 64-byte signature.
    pub fn schnorr_sign(&self, msg: &[u8; 32], privkey: &[u8; 32], aux_rand: &[u8; 32]) -> Result<[u8; 64]> {
        let mut sig = [0u8; 64];
        let rc = unsafe { ffi::secp256k1_schnorr_sign(msg.as_ptr(), privkey.as_ptr(), aux_rand.as_ptr(), sig.as_mut_ptr()) };
        if rc != 0 { return Err(Error::SigningFailed); }
        Ok(sig)
    }

    /// Verify BIP-340 Schnorr signature.
    pub fn schnorr_verify(&self, msg: &[u8; 32], sig: &[u8; 64], pubkey_x: &[u8; 32]) -> bool {
        unsafe { ffi::secp256k1_schnorr_verify(msg.as_ptr(), sig.as_ptr(), pubkey_x.as_ptr()) == 1 }
    }

    /// Get x-only public key (32 bytes) for Schnorr.
    pub fn schnorr_pubkey(&self, privkey: &[u8; 32]) -> Result<[u8; 32]> {
        let mut pubkey_x = [0u8; 32];
        let rc = unsafe { ffi::secp256k1_schnorr_pubkey(privkey.as_ptr(), pubkey_x.as_mut_ptr()) };
        if rc != 0 { return Err(Error::InvalidSecretKey); }
        Ok(pubkey_x)
    }

    // ── ECDH ─────────────────────────────────────────────────────────────

    /// ECDH shared secret: SHA256(compressed shared point).
    pub fn ecdh(&self, privkey: &[u8; 32], pubkey: &[u8; 33]) -> Result<[u8; 32]> {
        let mut secret = [0u8; 32];
        let rc = unsafe { ffi::secp256k1_ecdh(privkey.as_ptr(), pubkey.as_ptr(), secret.as_mut_ptr()) };
        if rc != 0 { return Err(Error::EcdhFailed); }
        Ok(secret)
    }

    /// ECDH x-only: SHA256(x-coordinate).
    pub fn ecdh_xonly(&self, privkey: &[u8; 32], pubkey: &[u8; 33]) -> Result<[u8; 32]> {
        let mut secret = [0u8; 32];
        let rc = unsafe { ffi::secp256k1_ecdh_xonly(privkey.as_ptr(), pubkey.as_ptr(), secret.as_mut_ptr()) };
        if rc != 0 { return Err(Error::EcdhFailed); }
        Ok(secret)
    }

    /// ECDH raw: raw x-coordinate of shared point.
    pub fn ecdh_raw(&self, privkey: &[u8; 32], pubkey: &[u8; 33]) -> Result<[u8; 32]> {
        let mut secret = [0u8; 32];
        let rc = unsafe { ffi::secp256k1_ecdh_raw(privkey.as_ptr(), pubkey.as_ptr(), secret.as_mut_ptr()) };
        if rc != 0 { return Err(Error::EcdhFailed); }
        Ok(secret)
    }

    // ── Hashing ──────────────────────────────────────────────────────────

    /// SHA-256 hash.
    pub fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut digest = [0u8; 32];
        unsafe { ffi::secp256k1_sha256(data.as_ptr(), data.len(), digest.as_mut_ptr()); }
        digest
    }

    /// HASH160: RIPEMD160(SHA256(data)).
    pub fn hash160(&self, data: &[u8]) -> [u8; 20] {
        let mut digest = [0u8; 20];
        unsafe { ffi::secp256k1_hash160(data.as_ptr(), data.len(), digest.as_mut_ptr()); }
        digest
    }

    /// BIP-340 tagged hash.
    pub fn tagged_hash(&self, tag: &str, data: &[u8]) -> [u8; 32] {
        let tag_c = CString::new(tag).expect("tag must not contain NUL");
        let mut digest = [0u8; 32];
        unsafe { ffi::secp256k1_tagged_hash(tag_c.as_ptr(), data.as_ptr(), data.len(), digest.as_mut_ptr()); }
        digest
    }

    // ── Bitcoin Addresses ────────────────────────────────────────────────

    /// Generate P2PKH address from compressed public key.
    pub fn address_p2pkh(&self, pubkey: &[u8; 33], network: Network) -> Result<String> {
        self.get_address(|buf, len| unsafe {
            ffi::secp256k1_address_p2pkh(pubkey.as_ptr(), network as i32, buf, len)
        })
    }

    /// Generate P2WPKH (SegWit v0) address from compressed public key.
    pub fn address_p2wpkh(&self, pubkey: &[u8; 33], network: Network) -> Result<String> {
        self.get_address(|buf, len| unsafe {
            ffi::secp256k1_address_p2wpkh(pubkey.as_ptr(), network as i32, buf, len)
        })
    }

    /// Generate P2TR (Taproot) address from x-only public key.
    pub fn address_p2tr(&self, internal_key_x: &[u8; 32], network: Network) -> Result<String> {
        self.get_address(|buf, len| unsafe {
            ffi::secp256k1_address_p2tr(internal_key_x.as_ptr(), network as i32, buf, len)
        })
    }

    // ── WIF ──────────────────────────────────────────────────────────────

    /// Encode private key as WIF string.
    pub fn wif_encode(&self, privkey: &[u8; 32], compressed: bool, network: Network) -> Result<String> {
        self.get_address(|buf, len| unsafe {
            ffi::secp256k1_wif_encode(
                privkey.as_ptr(), if compressed { 1 } else { 0 },
                network as i32, buf, len,
            )
        }).map_err(|_| Error::WifFailed)
    }

    /// Decode WIF string. Returns (privkey, compressed, network).
    pub fn wif_decode(&self, wif: &str) -> Result<([u8; 32], bool, Network)> {
        let wif_c = CString::new(wif).map_err(|_| Error::WifFailed)?;
        let mut privkey = [0u8; 32];
        let mut compressed: i32 = 0;
        let mut network: i32 = 0;
        let rc = unsafe {
            ffi::secp256k1_wif_decode(
                wif_c.as_ptr(), privkey.as_mut_ptr(),
                &mut compressed as *mut i32 as *mut std::os::raw::c_int,
                &mut network as *mut i32 as *mut std::os::raw::c_int,
            )
        };
        if rc != 0 { return Err(Error::WifFailed); }
        let net = if network == 1 { Network::Testnet } else { Network::Mainnet };
        Ok((privkey, compressed == 1, net))
    }

    // ── BIP-32 ───────────────────────────────────────────────────────────

    /// Create master key from seed (16-64 bytes).
    pub fn bip32_master_key(&self, seed: &[u8]) -> Result<ffi::secp256k1_bip32_key> {
        let mut key = ffi::secp256k1_bip32_key { data: [0u8; 78], is_private: 0 };
        let rc = unsafe { ffi::secp256k1_bip32_master_key(seed.as_ptr(), seed.len(), &mut key) };
        if rc != 0 { return Err(Error::Bip32Failed); }
        Ok(key)
    }

    /// Derive child key by index.
    pub fn bip32_derive_child(&self, parent: &ffi::secp256k1_bip32_key, index: u32) -> Result<ffi::secp256k1_bip32_key> {
        let mut child = ffi::secp256k1_bip32_key { data: [0u8; 78], is_private: 0 };
        let rc = unsafe { ffi::secp256k1_bip32_derive_child(parent, index, &mut child) };
        if rc != 0 { return Err(Error::Bip32Failed); }
        Ok(child)
    }

    /// Derive key from path string, e.g. "m/44'/0'/0'/0/0".
    pub fn bip32_derive_path(&self, master: &ffi::secp256k1_bip32_key, path: &str) -> Result<ffi::secp256k1_bip32_key> {
        let path_c = CString::new(path).map_err(|_| Error::Bip32Failed)?;
        let mut key = ffi::secp256k1_bip32_key { data: [0u8; 78], is_private: 0 };
        let rc = unsafe { ffi::secp256k1_bip32_derive_path(master, path_c.as_ptr(), &mut key) };
        if rc != 0 { return Err(Error::Bip32Failed); }
        Ok(key)
    }

    /// Get private key bytes from extended key.
    pub fn bip32_get_privkey(&self, key: &ffi::secp256k1_bip32_key) -> Result<[u8; 32]> {
        let mut privkey = [0u8; 32];
        let rc = unsafe { ffi::secp256k1_bip32_get_privkey(key, privkey.as_mut_ptr()) };
        if rc != 0 { return Err(Error::Bip32Failed); }
        Ok(privkey)
    }

    /// Get compressed public key from extended key.
    pub fn bip32_get_pubkey(&self, key: &ffi::secp256k1_bip32_key) -> Result<[u8; 33]> {
        let mut pubkey = [0u8; 33];
        let rc = unsafe { ffi::secp256k1_bip32_get_pubkey(key, pubkey.as_mut_ptr()) };
        if rc != 0 { return Err(Error::Bip32Failed); }
        Ok(pubkey)
    }

    // ── Taproot ──────────────────────────────────────────────────────────

    /// Derive Taproot output key. Returns (output_key_x, parity).
    pub fn taproot_output_key(&self, internal_key_x: &[u8; 32], merkle_root: Option<&[u8; 32]>) -> Result<([u8; 32], i32)> {
        let mut output_key_x = [0u8; 32];
        let mut parity: i32 = 0;
        let mr_ptr = merkle_root.map_or(std::ptr::null(), |r| r.as_ptr());
        let rc = unsafe {
            ffi::secp256k1_taproot_output_key(
                internal_key_x.as_ptr(), mr_ptr,
                output_key_x.as_mut_ptr(),
                &mut parity as *mut i32 as *mut std::os::raw::c_int,
            )
        };
        if rc != 0 { return Err(Error::TaprootFailed); }
        Ok((output_key_x, parity))
    }

    /// Tweak private key for Taproot key-path spending.
    pub fn taproot_tweak_privkey(&self, privkey: &[u8; 32], merkle_root: Option<&[u8; 32]>) -> Result<[u8; 32]> {
        let mut tweaked = [0u8; 32];
        let mr_ptr = merkle_root.map_or(std::ptr::null(), |r| r.as_ptr());
        let rc = unsafe { ffi::secp256k1_taproot_tweak_privkey(privkey.as_ptr(), mr_ptr, tweaked.as_mut_ptr()) };
        if rc != 0 { return Err(Error::TaprootFailed); }
        Ok(tweaked)
    }

    /// Verify Taproot commitment.
    pub fn taproot_verify_commitment(
        &self,
        output_key_x: &[u8; 32],
        output_key_parity: i32,
        internal_key_x: &[u8; 32],
        merkle_root: Option<&[u8]>,
    ) -> bool {
        let (mr_ptr, mr_len) = match merkle_root {
            Some(mr) => (mr.as_ptr(), mr.len()),
            None => (std::ptr::null(), 0),
        };
        unsafe {
            ffi::secp256k1_taproot_verify_commitment(
                output_key_x.as_ptr(), output_key_parity,
                internal_key_x.as_ptr(), mr_ptr, mr_len,
            ) == 1
        }
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    fn get_address(&self, f: impl FnOnce(*mut std::os::raw::c_char, *mut usize) -> i32) -> Result<String> {
        let mut buf = [0u8; 128];
        let mut len: usize = 128;
        let rc = f(buf.as_mut_ptr() as *mut std::os::raw::c_char, &mut len);
        if rc != 0 { return Err(Error::AddressFailed); }
        String::from_utf8(buf[..len].to_vec()).map_err(|_| Error::AddressFailed)
    }
}
