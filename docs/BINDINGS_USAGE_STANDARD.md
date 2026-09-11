# Binding Usage Standard
## UltrafastSecp256k1 Cross-Language Secure Usage Rules

> **Canonical document**: this is the one binding document that should be treated as the operational standard.
> Use it for day-to-day integration guidance. The supporting references remain:
> - `docs/BINDINGS_MEMORY_MODEL.md`
> - `docs/BINDINGS_EXAMPLES.md`
> - `docs/BINDINGS_ABI_COMPAT.md`

---

## 1. Scope

This document standardizes how UltrafastSecp256k1 bindings should be used across all supported languages:

- `c_api`
- `python`
- `nodejs`
- `csharp`
- `java`
- `swift`
- `go`
- `rust`
- `dart`
- `php`
- `ruby`
- `react-native`

The goal is not to pretend every runtime can securely erase memory equally well. The goal is to make the safest supported pattern explicit, repeatable, and hard to misuse.

---

## 2. Universal Rules

These rules apply in every language.

1. **Create one context per owner or thread.**
   Do not share a mutable `ufsecp` context across unrelated threads unless the binding explicitly guarantees that ownership model.

2. **Check ABI compatibility at initialization.**
   Every wrapper should gate initialization on `ufsecp_abi_version()`.

3. **Treat error-message pointers as borrowed.**
   `last_error_msg` style accessors expose borrowed strings that are only valid until the next mutating call on the same context or until destroy. Copy them immediately if you need to keep them.

4. **Destroy contexts deterministically.**
   Use `destroy`, `Dispose`, `defer`, `Drop`, `using`, or equivalent deterministic cleanup rather than relying on GC/finalizers.

5. **Keep secrets in mutable memory whenever the runtime permits it.**
   Immutable strings and immutable byte containers are the weakest option and should be avoided for private keys, aux randomness, seeds, and shared secrets.

6. **Zero secret material immediately after use.**
   This includes:
   - private keys
   - aux randomness
   - BIP-32 seeds
   - shared secrets
   - derived secret child keys

7. **Do not cache private keys inside long-lived wrapper objects.**
   Pass secrets per call. Wrapper instances should own contexts, not keys.

8. **Prefer short secret lifetimes.**
   Create the secret, use it, wipe it, destroy the context if the operation is complete.

9. **Do not log secret-bearing inputs or derived secrets.**
   Never log private keys, seeds, ECDH outputs, tweak inputs, or aux data.

10. **Assume the C ABI is the security floor.**
    The native library guarantees constant-time handling for secret-bearing CPU operations, per-call secret routing, nonce zeroization, and context scratch cleanup. Language runtimes may weaken the total system if the caller uses immutable or copied containers.

---

## 3. Standard Lifecycle

This is the standard lifecycle every binding should follow.

1. Create a context.
2. Prepare secret inputs in the most mutable container the language supports.
3. Perform the operation.
4. Zero secret inputs in `finally` or `defer` or `Drop` cleanup.
5. Destroy the context deterministically.

For verify-only and serialization-only workflows, no secret cleanup step is needed beyond normal context lifecycle management because the inputs are public.

---

## 4. Secret-Handling Standard By Language

| Language | Preferred Secret Container | Standard Cleanup | Standard Risk Level |
|---|---|---|---|
| C API | stack `uint8_t[32]` or caller-owned mutable buffer | `memset_explicit` or equivalent | Low |
| Python | `bytearray` | overwrite in `finally` | High |
| Node.js | `SensitiveBytes.take(...)` or mutable `Buffer` with `autoZeroInputs: true` | wrapper cleanup plus `bestEffortZero` or `fill(0)` | Medium |
| C# | `Span<byte>` or `byte[]` | `Clear()` or `Array.Clear()` | Medium |
| Java | `byte[]` | `Arrays.fill(..., (byte) 0)` | Medium |
| Swift | single-owner `Data` | `resetBytes(in:)` in `defer` | Low |
| Go | `[32]byte` | overwrite in `defer` loop | Low |
| Rust | `[u8; 32]` | `zeroize()` | Low |
| Dart | `Uint8List` | `fillRange(...)` in `finally` | Medium |
| PHP | short-lived binary string | `sodium_memzero` if available, otherwise overwrite and unset | High |
| Ruby | mutable binary `String` | `replace("\x00" * len)` in `ensure` | Medium |
| React Native | do not keep secrets in JS strings if avoidable | prefer native-owned key handles; if impossible, keep JS secret lifetime minimal | High |

---

## 5. Language Standards And Examples

### 5.1 C API

**Standard**

- Preferred for maximum control.
- Keep secret buffers caller-owned and mutable.
- Zero private key, aux buffer, and any derived secret output before return.
- Treat `ufsecp_error_str(err)` as display-only, not as a retained pointer contract.

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ufsecp/ufsecp.h"

int main(void) {
    ufsecp_ctx* ctx = NULL;
    uint8_t privkey[32] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    };
    uint8_t hash[32];
    uint8_t sig[64];
    uint8_t pubkey[33];
    ufsecp_error_t err = ufsecp_ctx_create(&ctx);
    if (err != UFSECP_OK) {
        fprintf(stderr, "ctx_create: %s\n", ufsecp_error_str(err));
        return 1;
    }

    ufsecp_sha256((const uint8_t*)"hello ufsecp", 12, hash);
    err = ufsecp_pubkey_create(ctx, privkey, pubkey);
    if (err == UFSECP_OK) {
        err = ufsecp_ecdsa_sign(ctx, hash, privkey, sig);
    }
    if (err == UFSECP_OK) {
        err = ufsecp_ecdsa_verify(ctx, hash, sig, pubkey);
        printf("verify: %s\n", err == UFSECP_OK ? "OK" : "FAIL");
    }

    memset_explicit(privkey, 0, sizeof(privkey));
    ufsecp_ctx_destroy(ctx);
    return err == UFSECP_OK ? 0 : 1;
}
```

**Do not**

- keep global contexts for unrelated workers
- retain borrowed error strings across later calls
- place long-lived secrets in immutable string literals or read-only memory

### 5.2 Python

**Standard**

- Do not treat `bytes` as a secure secret container.
- Prefer `bytearray` for secrets so the caller can wipe them.
- Convert to `bytes(...)` only at the call boundary if the wrapper API requires it.

```python
import os
from ufsecp import Ufsecp

with Ufsecp() as ctx:
    privkey = bytearray(os.urandom(32))
    try:
        while not ctx.seckey_verify(bytes(privkey)):
            privkey[:] = os.urandom(32)

        msg = ctx.sha256(b"binding standard")
        sig = ctx.ecdsa_sign(msg, bytes(privkey))
        pubkey = ctx.pubkey_create(bytes(privkey))
        assert ctx.ecdsa_verify(msg, sig, pubkey)
    finally:
        for i in range(len(privkey)):
            privkey[i] = 0
```

**Why**

- Python `bytes` is immutable and cannot be securely erased by the wrapper.
- The best supported pattern is mutable caller-owned storage plus explicit wiping.

### 5.3 Node.js

**Standard**

- Default to `new UfsecpContext({ autoZeroInputs: true })` for secret-bearing workflows.
- Prefer `SensitiveBytes.take(...)` so ownership is explicit and the wrapper can wipe on completion.
- Use `destroy()` or `Symbol.dispose` and do not rely on finalizers alone.

```javascript
const crypto = require('crypto');
const {
  UfsecpContext,
  SensitiveBytes,
  bestEffortZero,
} = require('@ultrafast/ufsecp');

const ctx = new UfsecpContext({ autoZeroInputs: true });
const secret = SensitiveBytes.take(crypto.randomBytes(32));

try {
  const msg = ctx.sha256(Buffer.from('binding standard'));
  const sig = ctx.ecdsaSign(msg, secret);
  const pubkey = ctx.pubkeyCreate(secret);
  console.log('valid:', ctx.ecdsaVerify(msg, sig, pubkey));
} finally {
  secret.destroy();
  ctx.destroy();
}
```

**Why**

- V8 cannot guarantee full heap erasure.
- The standard therefore minimizes mistakes mechanically: explicit ownership, wrapper `finally` cleanup, and opt-in automatic wiping for mutable inputs.

**Do not**

- keep private keys in plain JS strings
- reuse one `Buffer` across unrelated long-lived code paths
- assume GC finalization is timely enough for secret cleanup

### 5.4 C#

**Standard**

- Prefer `Span<byte>` or short-lived `byte[]`.
- Clear secret buffers in `finally`.
- Use `using` for deterministic context disposal.

```csharp
using System;
using System.Security.Cryptography;
using Ufsecp;

using var ctx = new Ufsecp.Ufsecp();
byte[] privkey = RandomNumberGenerator.GetBytes(32);

try {
    byte[] msg = ctx.Sha256(System.Text.Encoding.UTF8.GetBytes("binding standard"));
    byte[] sig = ctx.EcdsaSign(msg, privkey);
    byte[] pubkey = ctx.PubkeyCreate(privkey);
    Console.WriteLine($"valid: {ctx.EcdsaVerify(msg, sig, pubkey)}");
}
finally {
    Array.Clear(privkey, 0, privkey.Length);
}
```

**Why**

- Managed arrays may be copied by the runtime before pinning.
- The standard cannot eliminate that risk, but it does guarantee immediate caller-side cleanup.

### 5.5 Java

**Standard**

- Keep secrets in `byte[]`, not `String`.
- Always wipe with `Arrays.fill` in `finally`.
- Use `try-with-resources` for deterministic context closure.

```java
import com.ultrafast.ufsecp.Ufsecp;
import java.security.SecureRandom;
import java.util.Arrays;

try (Ufsecp ctx = new Ufsecp()) {
    byte[] privkey = new byte[32];
    SecureRandom.getInstanceStrong().nextBytes(privkey);
    try {
        byte[] msg = Ufsecp.sha256("binding standard".getBytes());
        byte[] sig = ctx.ecdsaSign(msg, privkey);
        byte[] pubkey = ctx.pubkeyCreate(privkey);
        System.out.println("valid: " + ctx.ecdsaVerify(msg, sig, pubkey));
    } finally {
        Arrays.fill(privkey, (byte) 0);
    }
}
```

**Why**

- The JVM may relocate arrays.
- This standard keeps secrets mutable, short-lived, and explicitly wiped.

### 5.6 Swift

**Standard**

- Use single-owner `Data` for secrets.
- Wipe with `resetBytes(in:)` in `defer`.
- Avoid sharing the same `Data` backing store across multiple references.

```swift
import Security
import Ufsecp

let ctx = try UfsecpContext()
var privkey = Data(count: 32)
_ = privkey.withUnsafeMutableBytes {
    SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
}

defer {
    privkey.resetBytes(in: 0..<privkey.count)
    ctx.destroy()
}

let msg = try ctx.sha256(Data("binding standard".utf8))
let sig = try ctx.ecdsaSign(msgHash: msg, privkey: privkey)
let pubkey = try ctx.pubkeyCreate(privkey: privkey)
print("valid:", try ctx.ecdsaVerify(msgHash: msg, sig: sig, pubkey: pubkey))
```

**Why**

- `Data` is mutable and works with C interop efficiently.
- Copy-on-write means you should avoid sharing secret `Data` values broadly.

### 5.7 Go

**Standard**

- Prefer fixed-size `[32]byte` for private keys.
- Wipe in a deferred loop.
- Destroy the context with `defer`.

```go
package main

import (
    "crypto/rand"
    "fmt"

    "github.com/nicenemo/ufsecp"
)

func main() {
    ctx, err := ufsecp.NewContext()
    if err != nil {
        panic(err)
    }
    defer ctx.Destroy()

    var privkey [32]byte
    if _, err := rand.Read(privkey[:]); err != nil {
        panic(err)
    }
    defer func() {
        for i := range privkey {
            privkey[i] = 0
        }
    }()

    msg, _ := ufsecp.SHA256([]byte("binding standard"))
    sig, _ := ctx.EcdsaSign(msg, privkey)
    pubkey, _ := ctx.PubkeyCreate(privkey)
    fmt.Println("valid:", ctx.EcdsaVerify(msg, sig, pubkey) == nil)
}
```

**Why**

- Fixed-size arrays encourage stack allocation and direct pointer passing.
- This is one of the strongest binding-side patterns outside Rust and raw C.

### 5.8 Rust

**Standard**

- Keep secrets in `[u8; 32]`.
- Use the `zeroize` crate for explicit cleanup.
- Prefer borrowed references over owned heap buffers where possible.

```rust
use rand::RngCore;
use ufsecp::Context;
use zeroize::Zeroize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context::new()?;
    let mut privkey = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut privkey);

    let msg = Context::sha256(b"binding standard")?;
    let sig = ctx.ecdsa_sign(&msg, &privkey)?;
    let pubkey = ctx.pubkey_create(&privkey)?;
    println!("valid: {}", ctx.ecdsa_verify(&msg, &sig, &pubkey));

    privkey.zeroize();
    Ok(())
}
```

**Why**

- Rust provides the cleanest secret ownership model among the managed bindings.
- No hidden copies are introduced by ordinary borrowed-slice usage.

### 5.9 Dart

**Standard**

- Use `Uint8List` for secrets.
- Overwrite with `fillRange` in `finally`.
- Destroy the context explicitly.

```dart
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:ultrafast_secp256k1/ufsecp.dart';

void main() {
  final ctx = UfsecpContext();
  final rng = Random.secure();
  final privkey = Uint8List(32);
  for (var i = 0; i < privkey.length; i++) {
    privkey[i] = rng.nextInt(256);
  }

  try {
        final msg = ctx.sha256(Uint8List.fromList(utf8.encode('binding standard')));
    final sig = ctx.ecdsaSign(msg, privkey);
    final pubkey = ctx.pubkeyCreate(privkey);
    print('valid: ${ctx.ecdsaVerify(msg, sig, pubkey)}');
  } finally {
    privkey.fillRange(0, privkey.length, 0);
    ctx.destroy();
  }
}
```

**Why**

- Dart FFI uses native temporary buffers, but the Dart VM may still retain copied heap state.
- The standard therefore enforces explicit caller-side cleanup as well.

### 5.10 PHP

**Standard**

- PHP is a high-risk secret runtime because binary strings are not a strong secure-memory abstraction.
- Keep secret values short-lived.
- If `ext/sodium` is available, use `sodium_memzero` on the variable immediately after use.

```php
<?php

use Ultrafast\Ufsecp\Ufsecp;

$ctx = new Ufsecp();
$privkey = random_bytes(32);

try {
    $msg = Ufsecp::sha256('binding standard');
    $sig = $ctx->ecdsaSign($msg, $privkey);
    $pubkey = $ctx->pubkeyCreate($privkey);
    echo 'valid: ' . ($ctx->ecdsaVerify($msg, $sig, $pubkey) ? 'true' : 'false') . PHP_EOL;
} finally {
    if (function_exists('sodium_memzero')) {
        sodium_memzero($privkey);
    } else {
        $privkey = str_repeat("\0", strlen($privkey));
        unset($privkey);
    }
}
```

**Why**

- PHP cannot offer the same memory guarantees as Rust, Go, or raw C.
- The standard therefore minimizes lifetime and requires immediate best-effort cleanup.

### 5.11 Ruby

**Standard**

- Use mutable binary `String` values for secret inputs.
- Overwrite with zero bytes in `ensure`.
- Destroy the context explicitly.

```ruby
require 'securerandom'
require 'ufsecp'

ctx = Ufsecp::Context.new
privkey = SecureRandom.random_bytes(32)

begin
  msg = ctx.sha256('binding standard')
  sig = ctx.ecdsa_sign(msg, privkey)
  pubkey = ctx.pubkey_create(privkey)
  puts "valid: #{ctx.ecdsa_verify(msg, sig, pubkey)}"
ensure
  privkey.replace("\x00" * privkey.bytesize)
  ctx.destroy
end
```

**Why**

- Ruby strings are mutable, which makes them materially better than immutable runtime strings for secret cleanup.
- Native copies can still exist temporarily, so cleanup must still happen immediately.

### 5.12 React Native

**Standard**

- Do not treat JavaScript hex strings as a secure secret container.
- Preferred pattern: keep private keys in the native layer, device keystore, Secure Enclave, or Android Keystore, and expose signing through a native-owned handle or service.
- If the current bridge API must accept hex strings, keep secret lifetime as short as possible and do not reuse those strings across app state, logs, caches, or Redux-like stores.

```javascript
import { UfsecpContext } from 'react-native-ultrafast-secp256k1/lib/ufsecp';

const ctx = await UfsecpContext.create();

try {
  const pubkey = '02' + '11'.repeat(32);
  const msg = '22'.repeat(32);
  const sig = '33'.repeat(64);
  console.log('verify:', await ctx.ecdsaVerify(msg, sig, pubkey));
} finally {
  await ctx.destroy();
}
```

**Why**

- JavaScript strings are immutable and may be copied by the bridge and engine.
- For that reason, the cross-language standard does **not** treat React Native JS as an acceptable place for long-lived private key ownership.
- Secret-bearing operations should move native-side when the threat model is serious.

---

## 6. Error-Handling Standard

Across bindings, use the following rule:

- invalid secret-bearing construction or malformed inputs should raise or return an explicit error
- signature verification failure should be treated as a normal negative result, not an exceptional crash path, when the binding exposes verify as boolean-style behavior
- if you need to retain `last_error_msg`, copy it immediately because the underlying pointer is borrowed

---

## 7. Anti-Patterns

These are out of standard.

- storing private keys in immutable strings when a mutable byte container exists
- relying on finalizers or GC for secret cleanup
- persisting private keys in wrapper instance fields
- logging private keys, seeds, aux buffers, or ECDH outputs
- sharing one mutable context across unrelated threads without an explicit ownership rule
- retaining borrowed native error pointers after later API calls
- keeping React Native secret hex strings in app state containers

---

## 8. Relationship To Supporting Docs

- `docs/BINDINGS_MEMORY_MODEL.md`: threat-model and runtime-boundary detail
- `docs/BINDINGS_EXAMPLES.md`: broader cookbook examples
- `docs/BINDINGS_ABI_COMPAT.md`: ABI version gate policy

Use this document when deciding how code **should** be written. Use the others when you need deeper rationale or extra examples.