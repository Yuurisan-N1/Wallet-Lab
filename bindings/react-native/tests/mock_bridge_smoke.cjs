const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const KNOWN_PRIVKEY = '0000000000000000000000000000000000000000000000000000000000000001';
const K2 = '0000000000000000000000000000000000000000000000000000000000000002';
const KNOWN_PUBKEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const KNOWN_PUBKEY_K2 = '02c6047f9441ed7d6d3045406e95c07cd85a2a7d1d39b3c3a1b7f9d37b8d6f4b6f';
const KNOWN_XONLY = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const SHA256_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const ECDSA_SIG = '11'.repeat(64);
const SCHNORR_SIG = '22'.repeat(64);
const SHARED_SECRET = '33'.repeat(32);
const WIF = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M8naorSxj5hH9w';

function loadUfsecpContext(mockReactNative) {
  const filePath = path.join(__dirname, '..', 'lib', 'ufsecp.js');
  const source = fs.readFileSync(filePath, 'utf8');
  const transformed = source
    .replace("import { NativeModules, Platform } from 'react-native';", 'const { NativeModules, Platform } = reactNative;')
    .replace(/export \{ UfsecpContext, UfsecpError \};\s*export default UfsecpContext;\s*$/m, 'module.exports = { UfsecpContext, UfsecpError, default: UfsecpContext };');

  const wrapped = `(function (reactNative, module, exports, require, console, setTimeout, clearTimeout) {\n${transformed}\n})`;
  const script = new vm.Script(wrapped, { filename: filePath });
  const fn = script.runInNewContext({});
  const module = { exports: {} };
  fn(mockReactNative, module, module.exports, require, console, setTimeout, clearTimeout);
  return module.exports.UfsecpContext;
}

function createNativeMock() {
  const handles = new Set();
  let nextHandle = 1;

  function requireHandle(handle) {
    if (!handles.has(handle)) {
      throw new Error('invalid context handle');
    }
  }

  function pubkeyFor(privkeyHex) {
    if (privkeyHex === KNOWN_PRIVKEY) return KNOWN_PUBKEY;
    if (privkeyHex === K2) return KNOWN_PUBKEY_K2;
    throw new Error('invalid private key');
  }

  return {
    NativeModules: {
      Ufsecp: {
        abiVersion: async () => 1,
        version: async () => 0x010000,
        versionString: async () => '1.0.0',
        create: async () => {
          const handle = nextHandle++;
          handles.add(handle);
          return handle;
        },
        destroy: async (handle) => {
          handles.delete(handle);
        },
        pubkeyCreate: async (handle, privkeyHex) => {
          requireHandle(handle);
          return pubkeyFor(privkeyHex);
        },
        pubkeyXonly: async (handle, privkeyHex) => {
          requireHandle(handle);
          if (privkeyHex !== KNOWN_PRIVKEY) throw new Error('invalid private key');
          return KNOWN_XONLY;
        },
        ecdsaSign: async (handle, msgHex, privkeyHex) => {
          requireHandle(handle);
          if (msgHex.length !== 64 || privkeyHex !== KNOWN_PRIVKEY) throw new Error('sign failed');
          return ECDSA_SIG;
        },
        ecdsaVerify: async (handle, msgHex, sigHex, pubkeyHex) => {
          requireHandle(handle);
          return msgHex.length === 64 && sigHex === ECDSA_SIG && pubkeyHex === KNOWN_PUBKEY;
        },
        schnorrSign: async (handle, msgHex, privkeyHex, auxHex) => {
          requireHandle(handle);
          if (msgHex.length !== 64 || privkeyHex !== KNOWN_PRIVKEY || auxHex.length !== 64) throw new Error('schnorr sign failed');
          return SCHNORR_SIG;
        },
        schnorrVerify: async (handle, msgHex, sigHex, pubkeyHex) => {
          requireHandle(handle);
          return msgHex.length === 64 && sigHex === SCHNORR_SIG && pubkeyHex === KNOWN_XONLY;
        },
        ecdsaSignRecoverable: async (handle, msgHex, privkeyHex) => {
          requireHandle(handle);
          if (msgHex.length !== 64 || privkeyHex !== KNOWN_PRIVKEY) throw new Error('recoverable sign failed');
          return { signature: ECDSA_SIG, recoveryId: 0 };
        },
        ecdsaRecover: async (handle, msgHex, sigHex, recoveryId) => {
          requireHandle(handle);
          if (msgHex.length !== 64 || sigHex !== ECDSA_SIG || recoveryId !== 0) throw new Error('recover failed');
          return KNOWN_PUBKEY;
        },
        sha256: async (dataHex) => {
          if (dataHex !== '') throw new Error('unexpected test input');
          return SHA256_EMPTY;
        },
        addrP2wpkh: async (handle, pubkeyHex, network) => {
          requireHandle(handle);
          if (pubkeyHex !== KNOWN_PUBKEY || network !== 0) throw new Error('address failed');
          return 'bc1qexampleaddress';
        },
        wifEncode: async (handle, privkeyHex, compressed, network) => {
          requireHandle(handle);
          if (privkeyHex !== KNOWN_PRIVKEY || compressed !== true || network !== 0) throw new Error('wif encode failed');
          return WIF;
        },
        wifDecode: async (handle, wif) => {
          requireHandle(handle);
          if (wif !== WIF) throw new Error('wif decode failed');
          return { privkey: KNOWN_PRIVKEY, compressed: true, network: 0 };
        },
        ecdh: async (handle, privkeyHex, pubkeyHex) => {
          requireHandle(handle);
          const validPair =
            (privkeyHex === KNOWN_PRIVKEY && pubkeyHex === KNOWN_PUBKEY_K2) ||
            (privkeyHex === K2 && pubkeyHex === KNOWN_PUBKEY);
          if (!validPair) throw new Error('ecdh failed');
          return SHARED_SECRET;
        },
      },
    },
    Platform: {
      select(value) {
        return value.default ?? value.ios ?? value.android;
      },
    },
  };
}

async function main() {
  const mockReactNative = createNativeMock();
  const UfsecpContext = loadUfsecpContext(mockReactNative);
  const tests = [];
  const test = (name, fn) => tests.push({ name, fn });

  test('ctx_create_abi', async () => {
    const abi = await UfsecpContext.abiVersion();
    assert(abi >= 1);
    const ctx = await UfsecpContext.create();
    await ctx.destroy();
  });

  test('pubkey_create_golden', async () => {
    const ctx = await UfsecpContext.create();
    assert.strictEqual(await ctx.pubkeyCreate(KNOWN_PRIVKEY), KNOWN_PUBKEY);
    await ctx.destroy();
  });

  test('pubkey_xonly_golden', async () => {
    const ctx = await UfsecpContext.create();
    assert.strictEqual(await ctx.pubkeyXonly(KNOWN_PRIVKEY), KNOWN_XONLY);
    await ctx.destroy();
  });

  test('ecdsa_sign_verify', async () => {
    const ctx = await UfsecpContext.create();
    const sig = await ctx.ecdsaSign('00'.repeat(32), KNOWN_PRIVKEY);
    assert.strictEqual(sig.length, 128);
    assert.strictEqual(await ctx.ecdsaVerify('00'.repeat(32), sig, KNOWN_PUBKEY), true);
    assert.strictEqual(await ctx.ecdsaVerify('00'.repeat(32), 'ff' + sig.slice(2), KNOWN_PUBKEY), false);
    await ctx.destroy();
  });

  test('schnorr_sign_verify', async () => {
    const ctx = await UfsecpContext.create();
    const sig = await ctx.schnorrSign('00'.repeat(32), KNOWN_PRIVKEY, '00'.repeat(32));
    assert.strictEqual(sig.length, 128);
    assert.strictEqual(await ctx.schnorrVerify('00'.repeat(32), sig, KNOWN_XONLY), true);
    assert.strictEqual(await ctx.schnorrVerify('00'.repeat(32), 'ff' + sig.slice(2), KNOWN_XONLY), false);
    await ctx.destroy();
  });

  test('ecdsa_recover', async () => {
    const ctx = await UfsecpContext.create();
    const { signature, recoveryId } = await ctx.ecdsaSignRecoverable('00'.repeat(32), KNOWN_PRIVKEY);
    assert.strictEqual(recoveryId, 0);
    assert.strictEqual(await ctx.ecdsaRecover('00'.repeat(32), signature, recoveryId), KNOWN_PUBKEY);
    await ctx.destroy();
  });

  test('sha256_golden', async () => {
    assert.strictEqual(await UfsecpContext.sha256(''), SHA256_EMPTY);
  });

  test('addr_p2wpkh', async () => {
    const ctx = await UfsecpContext.create();
    const addr = await ctx.addrP2wpkh(KNOWN_PUBKEY, 0);
    assert(addr.startsWith('bc1q'));
    await ctx.destroy();
  });

  test('wif_roundtrip', async () => {
    const ctx = await UfsecpContext.create();
    const wif = await ctx.wifEncode(KNOWN_PRIVKEY, true, 0);
    const decoded = await ctx.wifDecode(wif);
    assert.strictEqual(decoded.privkey, KNOWN_PRIVKEY);
    assert.strictEqual(decoded.compressed, true);
    assert.strictEqual(decoded.network, 0);
    await ctx.destroy();
  });

  test('ecdh_symmetric', async () => {
    const ctx = await UfsecpContext.create();
    const pub1 = await ctx.pubkeyCreate(KNOWN_PRIVKEY);
    const pub2 = await ctx.pubkeyCreate(K2);
    assert.strictEqual(await ctx.ecdh(KNOWN_PRIVKEY, pub2), await ctx.ecdh(K2, pub1));
    await ctx.destroy();
  });

  test('error_path', async () => {
    const ctx = await UfsecpContext.create();
    await assert.rejects(() => ctx.pubkeyCreate('00'.repeat(32)));
    await ctx.destroy();
  });

  test('destroy_guard', async () => {
    const ctx = await UfsecpContext.create();
    await ctx.destroy();
    await assert.rejects(() => ctx.pubkeyCreate(KNOWN_PRIVKEY));
  });

  let passed = 0;
  let failed = 0;
  for (const { name, fn } of tests) {
    try {
      await fn();
      console.log(`  [OK] ${name}`);
      passed++;
    } catch (error) {
      console.log(`  [FAIL] ${name}: ${error.message}`);
      failed++;
    }
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log(`  React Native contract smoke test: ${passed} passed, ${failed} failed`);
  console.log(`${'='.repeat(60)}`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});