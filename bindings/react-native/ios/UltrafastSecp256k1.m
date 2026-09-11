#import "UltrafastSecp256k1.h"
#import <React/RCTUtils.h>
#include "ultrafast_secp256k1.h"

@implementation UltrafastSecp256k1

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup { return NO; }

// ── Hex helpers ──────────────────────────────────────────────────────────────

static NSData *hexToData(NSString *hex) {
    NSMutableData *data = [NSMutableData dataWithCapacity:hex.length / 2];
    unsigned char byte;
    char buf[3] = {0};
    for (NSUInteger i = 0; i < hex.length; i += 2) {
        buf[0] = [hex characterAtIndex:i];
        buf[1] = [hex characterAtIndex:i + 1];
        byte = strtol(buf, NULL, 16);
        [data appendBytes:&byte length:1];
    }
    return data;
}

static NSString *dataToHex(const uint8_t *bytes, size_t length) {
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
    for (size_t i = 0; i < length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return hex;
}

// ── Init ─────────────────────────────────────────────────────────────────────

- (instancetype)init {
    self = [super init];
    if (self) { secp256k1_init(); }
    return self;
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(version) {
    return [NSString stringWithUTF8String:secp256k1_version()];
}

// ── Key Operations ───────────────────────────────────────────────────────────

RCT_EXPORT_METHOD(ecPubkeyCreate:(NSString *)privkeyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *pk = hexToData(privkeyHex);
    uint8_t out[33];
    if (secp256k1_ec_pubkey_create(pk.bytes, out) != 0) {
        reject(@"ERR", @"Invalid private key", nil);
        return;
    }
    resolve(dataToHex(out, 33));
}

RCT_EXPORT_METHOD(ecPubkeyCreateUncompressed:(NSString *)privkeyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *pk = hexToData(privkeyHex);
    uint8_t out[65];
    if (secp256k1_ec_pubkey_create_uncompressed(pk.bytes, out) != 0) {
        reject(@"ERR", @"Invalid private key", nil);
        return;
    }
    resolve(dataToHex(out, 65));
}

RCT_EXPORT_METHOD(ecPubkeyParse:(NSString *)pubkeyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *inp = hexToData(pubkeyHex);
    uint8_t out[33];
    if (secp256k1_ec_pubkey_parse(inp.bytes, inp.length, out) != 0) {
        reject(@"ERR", @"Invalid public key", nil);
        return;
    }
    resolve(dataToHex(out, 33));
}

RCT_EXPORT_METHOD(ecSeckeyVerify:(NSString *)privkeyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *pk = hexToData(privkeyHex);
    resolve(@(secp256k1_ec_seckey_verify(pk.bytes) == 1));
}

RCT_EXPORT_METHOD(ecPrivkeyNegate:(NSString *)privkeyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSMutableData *pk = [hexToData(privkeyHex) mutableCopy];
    secp256k1_ec_privkey_negate(pk.mutableBytes);
    resolve(dataToHex(pk.bytes, 32));
}

RCT_EXPORT_METHOD(ecPrivkeyTweakAdd:(NSString *)privkeyHex
                  tweak:(NSString *)tweakHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSMutableData *pk = [hexToData(privkeyHex) mutableCopy];
    NSData *tw = hexToData(tweakHex);
    if (secp256k1_ec_privkey_tweak_add(pk.mutableBytes, tw.bytes) != 0) {
        reject(@"ERR", @"Tweak add failed", nil);
        return;
    }
    resolve(dataToHex(pk.bytes, 32));
}

RCT_EXPORT_METHOD(ecPrivkeyTweakMul:(NSString *)privkeyHex
                  tweak:(NSString *)tweakHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSMutableData *pk = [hexToData(privkeyHex) mutableCopy];
    NSData *tw = hexToData(tweakHex);
    if (secp256k1_ec_privkey_tweak_mul(pk.mutableBytes, tw.bytes) != 0) {
        reject(@"ERR", @"Tweak mul failed", nil);
        return;
    }
    resolve(dataToHex(pk.bytes, 32));
}

// ── ECDSA ────────────────────────────────────────────────────────────────────

RCT_EXPORT_METHOD(ecdsaSign:(NSString *)msgHashHex
                  privkey:(NSString *)privkeyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *mh = hexToData(msgHashHex);
    NSData *pk = hexToData(privkeyHex);
    uint8_t sig[64];
    if (secp256k1_ecdsa_sign(mh.bytes, pk.bytes, sig) != 0) {
        reject(@"ERR", @"ECDSA signing failed", nil);
        return;
    }
    resolve(dataToHex(sig, 64));
}

RCT_EXPORT_METHOD(ecdsaVerify:(NSString *)msgHashHex
                  sig:(NSString *)sigHex
                  pubkey:(NSString *)pubkeyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *mh = hexToData(msgHashHex);
    NSData *s = hexToData(sigHex);
    NSData *pk = hexToData(pubkeyHex);
    resolve(@(secp256k1_ecdsa_verify(mh.bytes, s.bytes, pk.bytes) == 1));
}

RCT_EXPORT_METHOD(ecdsaSerializeDer:(NSString *)sigHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *s = hexToData(sigHex);
    uint8_t der[72];
    size_t der_len = 72;
    if (secp256k1_ecdsa_signature_serialize_der(s.bytes, der, &der_len) != 0) {
        reject(@"ERR", @"DER serialization failed", nil);
        return;
    }
    resolve(dataToHex(der, der_len));
}

// ── Recovery ─────────────────────────────────────────────────────────────────

RCT_EXPORT_METHOD(ecdsaSignRecoverable:(NSString *)msgHashHex
                  privkey:(NSString *)privkeyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *mh = hexToData(msgHashHex);
    NSData *pk = hexToData(privkeyHex);
    uint8_t sig[64];
    int recid;
    if (secp256k1_ecdsa_sign_recoverable(mh.bytes, pk.bytes, sig, &recid) != 0) {
        reject(@"ERR", @"Recoverable signing failed", nil);
        return;
    }
    resolve(@{@"signature": dataToHex(sig, 64), @"recid": @(recid)});
}

RCT_EXPORT_METHOD(ecdsaRecover:(NSString *)msgHashHex
                  sig:(NSString *)sigHex
                  recid:(int)recid
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *mh = hexToData(msgHashHex);
    NSData *s = hexToData(sigHex);
    uint8_t pubkey[33];
    if (secp256k1_ecdsa_recover(mh.bytes, s.bytes, recid, pubkey) != 0) {
        reject(@"ERR", @"Recovery failed", nil);
        return;
    }
    resolve(dataToHex(pubkey, 33));
}

// ── Schnorr ──────────────────────────────────────────────────────────────────

RCT_EXPORT_METHOD(schnorrSign:(NSString *)msgHex
                  privkey:(NSString *)privkeyHex
                  auxRand:(NSString *)auxRandHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *m = hexToData(msgHex);
    NSData *pk = hexToData(privkeyHex);
    NSData *ar = hexToData(auxRandHex);
    uint8_t sig[64];
    if (secp256k1_schnorr_sign(m.bytes, pk.bytes, ar.bytes, sig) != 0) {
        reject(@"ERR", @"Schnorr sign failed", nil);
        return;
    }
    resolve(dataToHex(sig, 64));
}

RCT_EXPORT_METHOD(schnorrVerify:(NSString *)msgHex
                  sig:(NSString *)sigHex
                  pubkeyX:(NSString *)pubkeyXHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *m = hexToData(msgHex);
    NSData *s = hexToData(sigHex);
    NSData *px = hexToData(pubkeyXHex);
    resolve(@(secp256k1_schnorr_verify(m.bytes, s.bytes, px.bytes) == 1));
}

RCT_EXPORT_METHOD(schnorrPubkey:(NSString *)privkeyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *pk = hexToData(privkeyHex);
    uint8_t out[32];
    if (secp256k1_schnorr_pubkey(pk.bytes, out) != 0) {
        reject(@"ERR", @"Invalid private key", nil);
        return;
    }
    resolve(dataToHex(out, 32));
}

// ── ECDH ─────────────────────────────────────────────────────────────────────

RCT_EXPORT_METHOD(ecdh:(NSString *)privkeyHex
                  pubkey:(NSString *)pubkeyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *pk = hexToData(privkeyHex);
    NSData *pub = hexToData(pubkeyHex);
    uint8_t out[32];
    if (secp256k1_ecdh(pk.bytes, pub.bytes, out) != 0) {
        reject(@"ERR", @"ECDH failed", nil); return;
    }
    resolve(dataToHex(out, 32));
}

RCT_EXPORT_METHOD(ecdhXonly:(NSString *)privkeyHex
                  pubkey:(NSString *)pubkeyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *pk = hexToData(privkeyHex);
    NSData *pub = hexToData(pubkeyHex);
    uint8_t out[32];
    if (secp256k1_ecdh_xonly(pk.bytes, pub.bytes, out) != 0) {
        reject(@"ERR", @"ECDH xonly failed", nil); return;
    }
    resolve(dataToHex(out, 32));
}

RCT_EXPORT_METHOD(ecdhRaw:(NSString *)privkeyHex
                  pubkey:(NSString *)pubkeyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *pk = hexToData(privkeyHex);
    NSData *pub = hexToData(pubkeyHex);
    uint8_t out[32];
    if (secp256k1_ecdh_raw(pk.bytes, pub.bytes, out) != 0) {
        reject(@"ERR", @"ECDH raw failed", nil); return;
    }
    resolve(dataToHex(out, 32));
}

// ── Hashing ──────────────────────────────────────────────────────────────────

RCT_EXPORT_METHOD(sha256:(NSString *)dataHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *d = hexToData(dataHex);
    uint8_t out[32];
    secp256k1_sha256(d.bytes, d.length, out);
    resolve(dataToHex(out, 32));
}

RCT_EXPORT_METHOD(hash160:(NSString *)dataHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *d = hexToData(dataHex);
    uint8_t out[20];
    secp256k1_hash160(d.bytes, d.length, out);
    resolve(dataToHex(out, 20));
}

RCT_EXPORT_METHOD(taggedHash:(NSString *)tag
                  data:(NSString *)dataHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *d = hexToData(dataHex);
    uint8_t out[32];
    secp256k1_tagged_hash(tag.UTF8String, d.bytes, d.length, out);
    resolve(dataToHex(out, 32));
}

// ── Addresses ────────────────────────────────────────────────────────────────

RCT_EXPORT_METHOD(addressP2PKH:(NSString *)pubkeyHex
                  network:(int)network
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *pk = hexToData(pubkeyHex);
    char addr[128]; size_t alen = 128;
    if (secp256k1_address_p2pkh(pk.bytes, network, addr, &alen) != 0) {
        reject(@"ERR", @"P2PKH failed", nil); return;
    }
    resolve([[NSString alloc] initWithBytes:addr length:alen encoding:NSUTF8StringEncoding]);
}

RCT_EXPORT_METHOD(addressP2WPKH:(NSString *)pubkeyHex
                  network:(int)network
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *pk = hexToData(pubkeyHex);
    char addr[128]; size_t alen = 128;
    if (secp256k1_address_p2wpkh(pk.bytes, network, addr, &alen) != 0) {
        reject(@"ERR", @"P2WPKH failed", nil); return;
    }
    resolve([[NSString alloc] initWithBytes:addr length:alen encoding:NSUTF8StringEncoding]);
}

RCT_EXPORT_METHOD(addressP2TR:(NSString *)internalKeyXHex
                  network:(int)network
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *ik = hexToData(internalKeyXHex);
    char addr[128]; size_t alen = 128;
    if (secp256k1_address_p2tr(ik.bytes, network, addr, &alen) != 0) {
        reject(@"ERR", @"P2TR failed", nil); return;
    }
    resolve([[NSString alloc] initWithBytes:addr length:alen encoding:NSUTF8StringEncoding]);
}

// ── WIF ──────────────────────────────────────────────────────────────────────

RCT_EXPORT_METHOD(wifEncode:(NSString *)privkeyHex
                  compressed:(BOOL)compressed
                  network:(int)network
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *pk = hexToData(privkeyHex);
    char wif[128]; size_t wlen = 128;
    if (secp256k1_wif_encode(pk.bytes, compressed ? 1 : 0, network, wif, &wlen) != 0) {
        reject(@"ERR", @"WIF encode failed", nil); return;
    }
    resolve([[NSString alloc] initWithBytes:wif length:wlen encoding:NSUTF8StringEncoding]);
}

RCT_EXPORT_METHOD(wifDecode:(NSString *)wif
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    uint8_t pk[32]; int comp, net;
    if (secp256k1_wif_decode(wif.UTF8String, pk, &comp, &net) != 0) {
        reject(@"ERR", @"Invalid WIF", nil); return;
    }
    resolve(@{
        @"privkey": dataToHex(pk, 32),
        @"compressed": @(comp == 1),
        @"network": @(net)
    });
}

// ── BIP-32 ───────────────────────────────────────────────────────────────────

RCT_EXPORT_METHOD(bip32MasterKey:(NSString *)seedHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *seed = hexToData(seedHex);
    secp256k1_bip32_key key;
    if (secp256k1_bip32_master_key(seed.bytes, seed.length, &key) != 0) {
        reject(@"ERR", @"Master key failed", nil); return;
    }
    resolve(dataToHex((const uint8_t *)&key, 79));
}

RCT_EXPORT_METHOD(bip32DeriveChild:(NSString *)parentKeyHex
                  index:(int)index
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *pdata = hexToData(parentKeyHex);
    secp256k1_bip32_key parent, child;
    memcpy(&parent, pdata.bytes, 79);
    if (secp256k1_bip32_derive_child(&parent, (uint32_t)index, &child) != 0) {
        reject(@"ERR", @"Derive child failed", nil); return;
    }
    resolve(dataToHex((const uint8_t *)&child, 79));
}

RCT_EXPORT_METHOD(bip32DerivePath:(NSString *)masterKeyHex
                  path:(NSString *)path
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *mdata = hexToData(masterKeyHex);
    secp256k1_bip32_key master, out;
    memcpy(&master, mdata.bytes, 79);
    if (secp256k1_bip32_derive_path(&master, path.UTF8String, &out) != 0) {
        reject(@"ERR", @"Path derivation failed", nil); return;
    }
    resolve(dataToHex((const uint8_t *)&out, 79));
}

RCT_EXPORT_METHOD(bip32GetPrivkey:(NSString *)keyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *kdata = hexToData(keyHex);
    secp256k1_bip32_key k;
    memcpy(&k, kdata.bytes, 79);
    uint8_t pk[32];
    if (secp256k1_bip32_get_privkey(&k, pk) != 0) {
        reject(@"ERR", @"Not a private key", nil); return;
    }
    resolve(dataToHex(pk, 32));
}

RCT_EXPORT_METHOD(bip32GetPubkey:(NSString *)keyHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *kdata = hexToData(keyHex);
    secp256k1_bip32_key k;
    memcpy(&k, kdata.bytes, 79);
    uint8_t pub[33];
    if (secp256k1_bip32_get_pubkey(&k, pub) != 0) {
        reject(@"ERR", @"Pubkey extraction failed", nil); return;
    }
    resolve(dataToHex(pub, 33));
}

// ── Taproot ──────────────────────────────────────────────────────────────────

RCT_EXPORT_METHOD(taprootOutputKey:(NSString *)internalKeyXHex
                  merkleRoot:(NSString *)merkleRootHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *ik = hexToData(internalKeyXHex);
    NSData *mr = merkleRootHex ? hexToData(merkleRootHex) : nil;
    uint8_t out[32]; int parity;
    if (secp256k1_taproot_output_key(ik.bytes, mr ? mr.bytes : NULL, out, &parity) != 0) {
        reject(@"ERR", @"Taproot output key failed", nil); return;
    }
    resolve(@{@"outputKeyX": dataToHex(out, 32), @"parity": @(parity)});
}

RCT_EXPORT_METHOD(taprootTweakPrivkey:(NSString *)privkeyHex
                  merkleRoot:(NSString *)merkleRootHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *pk = hexToData(privkeyHex);
    NSData *mr = merkleRootHex ? hexToData(merkleRootHex) : nil;
    uint8_t out[32];
    if (secp256k1_taproot_tweak_privkey(pk.bytes, mr ? mr.bytes : NULL, out) != 0) {
        reject(@"ERR", @"Taproot tweak failed", nil); return;
    }
    resolve(dataToHex(out, 32));
}

RCT_EXPORT_METHOD(taprootVerifyCommitment:(NSString *)outputKeyXHex
                  parity:(int)parity
                  internalKeyX:(NSString *)internalKeyXHex
                  merkleRoot:(NSString *)merkleRootHex
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject) {
    NSData *ok = hexToData(outputKeyXHex);
    NSData *ik = hexToData(internalKeyXHex);
    NSData *mr = merkleRootHex ? hexToData(merkleRootHex) : nil;
    int rc = secp256k1_taproot_verify_commitment(
        ok.bytes, parity, ik.bytes, mr ? mr.bytes : NULL, mr ? mr.length : 0);
    resolve(@(rc == 1));
}

@end
