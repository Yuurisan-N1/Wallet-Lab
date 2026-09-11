/**
 * UltrafastSecp256k1 — TypeScript type definitions
 */

export declare const NETWORK_MAINNET: 0;
export declare const NETWORK_TESTNET: 1;

export interface Secp256k1Options {
    libPath?: string;
    autoZeroInputs?: boolean;
}

export declare function bestEffortZero(buf: Buffer | Uint8Array): Buffer | Uint8Array;

export declare class SensitiveBytes {
    constructor(buf: Buffer | Uint8Array, options?: { copy?: boolean });
    static take(buf: Buffer | Uint8Array): SensitiveBytes;
    static copy(buf: Buffer | Uint8Array): SensitiveBytes;
    readonly bytes: Buffer;
    destroy(): void;
}

export declare class Secp256k1 {
    constructor(libPath?: string, options?: Secp256k1Options);
    constructor(options?: Secp256k1Options);

    version(): string;

    // Key operations
    ecPubkeyCreate(privkey: Buffer | Uint8Array | SensitiveBytes): Buffer;
    ecPubkeyCreateUncompressed(privkey: Buffer | Uint8Array | SensitiveBytes): Buffer;
    ecPubkeyParse(pubkey: Buffer | Uint8Array): Buffer;
    ecSeckeyVerify(privkey: Buffer | Uint8Array | SensitiveBytes): boolean;
    ecPrivkeyNegate(privkey: Buffer | Uint8Array | SensitiveBytes): Buffer;
    ecPrivkeyTweakAdd(privkey: Buffer | Uint8Array | SensitiveBytes, tweak: Buffer | Uint8Array | SensitiveBytes): Buffer;
    ecPrivkeyTweakMul(privkey: Buffer | Uint8Array | SensitiveBytes, tweak: Buffer | Uint8Array | SensitiveBytes): Buffer;

    // ECDSA
    ecdsaSign(msgHash: Buffer | Uint8Array, privkey: Buffer | Uint8Array | SensitiveBytes): Buffer;
    ecdsaVerify(msgHash: Buffer | Uint8Array, sig: Buffer | Uint8Array, pubkey: Buffer | Uint8Array): boolean;
    ecdsaSerializeDer(sig: Buffer | Uint8Array): Buffer;

    // Recovery
    ecdsaSignRecoverable(msgHash: Buffer | Uint8Array, privkey: Buffer | Uint8Array | SensitiveBytes): { signature: Buffer; recoveryId: number };
    ecdsaRecover(msgHash: Buffer | Uint8Array, sig: Buffer | Uint8Array, recid: number): Buffer;

    // Schnorr (BIP-340)
    schnorrSign(msg: Buffer | Uint8Array, privkey: Buffer | Uint8Array | SensitiveBytes, auxRand: Buffer | Uint8Array | SensitiveBytes): Buffer;
    schnorrVerify(msg: Buffer | Uint8Array, sig: Buffer | Uint8Array, pubkeyX: Buffer | Uint8Array): boolean;
    schnorrPubkey(privkey: Buffer | Uint8Array | SensitiveBytes): Buffer;

    // ECDH
    ecdh(privkey: Buffer | Uint8Array | SensitiveBytes, pubkey: Buffer | Uint8Array): Buffer;
    ecdhXonly(privkey: Buffer | Uint8Array | SensitiveBytes, pubkey: Buffer | Uint8Array): Buffer;
    ecdhRaw(privkey: Buffer | Uint8Array | SensitiveBytes, pubkey: Buffer | Uint8Array): Buffer;

    // Hashing
    sha256(data: Buffer | Uint8Array): Buffer;
    hash160(data: Buffer | Uint8Array): Buffer;
    taggedHash(tag: string, data: Buffer | Uint8Array): Buffer;

    // Addresses
    addressP2PKH(pubkey: Buffer | Uint8Array, network?: number): string;
    addressP2WPKH(pubkey: Buffer | Uint8Array, network?: number): string;
    addressP2TR(internalKeyX: Buffer | Uint8Array, network?: number): string;

    // WIF
    wifEncode(privkey: Buffer | Uint8Array | SensitiveBytes, compressed?: boolean, network?: number): string;
    wifDecode(wif: string): { privkey: Buffer; compressed: boolean; network: number };

    // BIP-32
    bip32MasterKey(seed: Buffer | Uint8Array): Buffer;
    bip32DerivePath(masterKey: Buffer | Uint8Array, path: string): Buffer;
    bip32GetPrivkey(key: Buffer | Uint8Array): Buffer;
    bip32GetPubkey(key: Buffer | Uint8Array): Buffer;

    // Taproot
    taprootOutputKey(internalKeyX: Buffer | Uint8Array, merkleRoot?: Buffer | Uint8Array | null): { outputKeyX: Buffer; parity: number };
    taprootTweakPrivkey(privkey: Buffer | Uint8Array | SensitiveBytes, merkleRoot?: Buffer | Uint8Array | null): Buffer;
}
