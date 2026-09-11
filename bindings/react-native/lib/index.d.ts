export declare const NETWORK_MAINNET: number;
export declare const NETWORK_TESTNET: number;

export declare function version(): string;

// Key Operations
export declare function ecPubkeyCreate(privkeyHex: string): Promise<string>;
export declare function ecPubkeyCreateUncompressed(privkeyHex: string): Promise<string>;
export declare function ecPubkeyParse(pubkeyHex: string): Promise<string>;
export declare function ecSeckeyVerify(privkeyHex: string): Promise<boolean>;
export declare function ecPrivkeyNegate(privkeyHex: string): Promise<string>;
export declare function ecPrivkeyTweakAdd(privkeyHex: string, tweakHex: string): Promise<string>;
export declare function ecPrivkeyTweakMul(privkeyHex: string, tweakHex: string): Promise<string>;

// ECDSA
export declare function ecdsaSign(msgHashHex: string, privkeyHex: string): Promise<string>;
export declare function ecdsaVerify(msgHashHex: string, sigHex: string, pubkeyHex: string): Promise<boolean>;
export declare function ecdsaSerializeDer(sigHex: string): Promise<string>;

// Recovery
export declare function ecdsaSignRecoverable(msgHashHex: string, privkeyHex: string): Promise<{ signature: string; recid: number }>;
export declare function ecdsaRecover(msgHashHex: string, sigHex: string, recid: number): Promise<string>;

// Schnorr
export declare function schnorrSign(msgHex: string, privkeyHex: string, auxRandHex: string): Promise<string>;
export declare function schnorrVerify(msgHex: string, sigHex: string, pubkeyXHex: string): Promise<boolean>;
export declare function schnorrPubkey(privkeyHex: string): Promise<string>;

// ECDH
export declare function ecdh(privkeyHex: string, pubkeyHex: string): Promise<string>;
export declare function ecdhXonly(privkeyHex: string, pubkeyHex: string): Promise<string>;
export declare function ecdhRaw(privkeyHex: string, pubkeyHex: string): Promise<string>;

// Hashing
export declare function sha256(dataHex: string): Promise<string>;
export declare function hash160(dataHex: string): Promise<string>;
export declare function taggedHash(tag: string, dataHex: string): Promise<string>;

// Addresses
export declare function addressP2PKH(pubkeyHex: string, network?: number): Promise<string>;
export declare function addressP2WPKH(pubkeyHex: string, network?: number): Promise<string>;
export declare function addressP2TR(internalKeyXHex: string, network?: number): Promise<string>;

// WIF
export declare function wifEncode(privkeyHex: string, compressed?: boolean, network?: number): Promise<string>;
export declare function wifDecode(wif: string): Promise<{ privkey: string; compressed: boolean; network: number }>;

// BIP-32
export declare function bip32MasterKey(seedHex: string): Promise<string>;
export declare function bip32DeriveChild(parentKeyHex: string, index: number): Promise<string>;
export declare function bip32DerivePath(masterKeyHex: string, path: string): Promise<string>;
export declare function bip32GetPrivkey(keyHex: string): Promise<string>;
export declare function bip32GetPubkey(keyHex: string): Promise<string>;

// Taproot
export declare function taprootOutputKey(internalKeyXHex: string, merkleRootHex?: string | null): Promise<{ outputKeyX: string; parity: number }>;
export declare function taprootTweakPrivkey(privkeyHex: string, merkleRootHex?: string | null): Promise<string>;
export declare function taprootVerifyCommitment(outputKeyXHex: string, parity: number, internalKeyXHex: string, merkleRootHex?: string | null): Promise<boolean>;

// Helpers
export declare function toHex(data: string | Uint8Array | number[]): string;
export declare function fromHex(hex: string): Uint8Array;
