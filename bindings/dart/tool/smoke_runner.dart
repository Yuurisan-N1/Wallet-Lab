import 'dart:typed_data';

import 'package:ultrafast_secp256k1/ufsecp.dart';

Uint8List hexToBytes(String hex) {
  final result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

final knownPrivkey = hexToBytes(
    '0000000000000000000000000000000000000000000000000000000000000001');

final knownPubkey = hexToBytes(
    '0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');

final knownXonly = hexToBytes(
    '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');

final sha256Empty = hexToBytes(
    'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855');

final msg32 = Uint8List(32);
final aux32 = Uint8List(32);

void expectCondition(bool condition, String message) {
  if (!condition) {
    throw StateError(message);
  }
}

Future<int> main() async {
  final tests = <String, void Function()>{
    'ctx_create_abi': () {
      final ctx = UfsecpContext();
      try {
        expectCondition(ctx.abiVersion >= 1, 'ABI version < 1');
      } finally {
        ctx.destroy();
      }
    },
    'pubkey_create_golden': () {
      final ctx = UfsecpContext();
      try {
        final pub = ctx.pubkeyCreate(knownPrivkey);
        expectCondition(_bytesEqual(pub, knownPubkey), 'compressed pubkey mismatch');
      } finally {
        ctx.destroy();
      }
    },
    'pubkey_xonly_golden': () {
      final ctx = UfsecpContext();
      try {
        final xonly = ctx.pubkeyXonly(knownPrivkey);
        expectCondition(_bytesEqual(xonly, knownXonly), 'x-only pubkey mismatch');
      } finally {
        ctx.destroy();
      }
    },
    'ecdsa_sign_verify': () {
      final ctx = UfsecpContext();
      try {
        final sig = ctx.ecdsaSign(msg32, knownPrivkey);
        expectCondition(sig.length == 64, 'sig length mismatch');
        expectCondition(ctx.ecdsaVerify(msg32, sig, knownPubkey), 'valid sig rejected');
        final bad = Uint8List.fromList(sig);
        bad[0] ^= 0x01;
        expectCondition(!ctx.ecdsaVerify(msg32, bad, knownPubkey), 'mutated sig accepted');
      } finally {
        ctx.destroy();
      }
    },
    'schnorr_sign_verify': () {
      final ctx = UfsecpContext();
      try {
        final sig = ctx.schnorrSign(msg32, knownPrivkey, aux32);
        expectCondition(sig.length == 64, 'schnorr sig length mismatch');
        expectCondition(ctx.schnorrVerify(msg32, sig, knownXonly), 'valid schnorr sig rejected');
      } finally {
        ctx.destroy();
      }
    },
    'ecdsa_recover': () {
      final ctx = UfsecpContext();
      try {
        final rec = ctx.ecdsaSignRecoverable(msg32, knownPrivkey);
        expectCondition(rec.recoveryId >= 0 && rec.recoveryId <= 3, 'recovery id out of range');
        final pub = ctx.ecdsaRecover(msg32, rec.signature, rec.recoveryId);
        expectCondition(_bytesEqual(pub, knownPubkey), 'recovered pubkey mismatch');
      } finally {
        ctx.destroy();
      }
    },
    'sha256_golden': () {
      final ctx = UfsecpContext();
      try {
        final digest = ctx.sha256(Uint8List(0));
        expectCondition(_bytesEqual(digest, sha256Empty), 'sha256 empty mismatch');
      } finally {
        ctx.destroy();
      }
    },
    'addr_p2wpkh': () {
      final ctx = UfsecpContext();
      try {
        final addr = ctx.addrP2WPKH(knownPubkey, network: Network.mainnet);
        expectCondition(addr.startsWith('bc1q'), 'expected bc1q address');
      } finally {
        ctx.destroy();
      }
    },
    'wif_roundtrip': () {
      final ctx = UfsecpContext();
      try {
        final wif = ctx.wifEncode(knownPrivkey, compressed: true, network: Network.mainnet);
        final decoded = ctx.wifDecode(wif);
        expectCondition(_bytesEqual(decoded.privkey, knownPrivkey), 'wif privkey mismatch');
        expectCondition(decoded.compressed, 'wif compressed mismatch');
      } finally {
        ctx.destroy();
      }
    },
    'ecdh_symmetric': () {
      final ctx = UfsecpContext();
      try {
        final k2 = hexToBytes(
            '0000000000000000000000000000000000000000000000000000000000000002');
        final pub1 = ctx.pubkeyCreate(knownPrivkey);
        final pub2 = ctx.pubkeyCreate(k2);
        final s12 = ctx.ecdh(knownPrivkey, pub2);
        final s21 = ctx.ecdh(k2, pub1);
        expectCondition(_bytesEqual(s12, s21), 'ecdh symmetry mismatch');
      } finally {
        ctx.destroy();
      }
    },
    'error_path': () {
      final ctx = UfsecpContext();
      try {
        var threw = false;
        try {
          ctx.pubkeyCreate(Uint8List(32));
        } catch (_) {
          threw = true;
        }
        expectCondition(threw, 'zero key should fail');
      } finally {
        ctx.destroy();
      }
    },
    'ecdsa_deterministic': () {
      final ctx = UfsecpContext();
      try {
        final sig1 = ctx.ecdsaSign(msg32, knownPrivkey);
        final sig2 = ctx.ecdsaSign(msg32, knownPrivkey);
        expectCondition(_bytesEqual(sig1, sig2), 'ecdsa must be deterministic');
      } finally {
        ctx.destroy();
      }
    },
  };

  var passed = 0;
  var failed = 0;
  tests.forEach((name, fn) {
    try {
      fn();
      print('  [OK] $name');
      passed++;
    } catch (error) {
      print('  [FAIL] $name: $error');
      failed++;
    }
  });

  print('\n============================================================');
  print('  Dart smoke test: $passed passed, $failed failed');
  print('============================================================');
  return failed == 0 ? 0 : 1;
}

bool _bytesEqual(Uint8List left, Uint8List right) {
  if (left.length != right.length) {
    return false;
  }
  for (var i = 0; i < left.length; i++) {
    if (left[i] != right[i]) {
      return false;
    }
  }
  return true;
}