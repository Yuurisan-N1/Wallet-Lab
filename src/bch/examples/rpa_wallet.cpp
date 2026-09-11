// ============================================================================
// rpa_wallet.cpp — BCH Reusable Payment Addresses: complete end-to-end example
// ============================================================================
//
// Demonstrates the full RPA lifecycle:
//   1. Receiver generates a paycode (publish once, reuse forever)
//   2. Sender grinds a matching signature + creates the payment output
//   3. Receiver scans the blockchain and finds the payment
//
// Build: cmake -DSECP256K1_BUILD_BCH=ON && make rpa_wallet_example
// Run:   ./rpa_wallet_example
//
// Specification: github.com/imaginaryusername/Reusable_specs
// ============================================================================

#include "secp256k1/bch/rpa.hpp"
#include "secp256k1/bch/bch_scan.hpp"
#include "secp256k1/bch/cashaddr.hpp"
#include "secp256k1/ct/point.hpp"
#include "secp256k1/ct/sign.hpp"
#include "secp256k1/sha256.hpp"
#include "secp256k1/detail/secure_erase.hpp"
#include <cstdio>
#include <cstring>
#include <array>
#include <vector>
#include <random>

using namespace secp256k1::bch;
using secp256k1::fast::Scalar;
using secp256k1::fast::Point;

// ── Helpers ───────────────────────────────────────────────────────────────────

static Scalar make_privkey(uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::array<uint8_t, 32> b{};
    for (int i = 0; i < 4; ++i) {
        uint64_t v = rng();
        std::memcpy(b.data() + i * 8, &v, 8);
    }
    b[0] &= 0x3f;
    b[0] |= 0x01;
    Scalar s{};
    Scalar::parse_bytes_strict(b.data(), s);
    return s;
}

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("  %-24s: ", label);
    for (size_t i = 0; i < std::min(len, size_t(16)); ++i)
        printf("%02x", data[i]);
    if (len > 16) printf("...");
    printf("\n");
}

// ── Step 1: Receiver generates paycode ───────────────────────────────────────

struct ReceiverWallet {
    Scalar scan_privkey;
    Scalar spend_privkey;
    RpaPaycode paycode;
    std::string paycode_str;

    static ReceiverWallet generate(uint8_t prefix_bits = 8) {
        ReceiverWallet w;
        w.scan_privkey  = make_privkey(0xBCA5CA17u);
        w.spend_privkey = make_privkey(0xBCA55EA4u);

        w.paycode.version     = 1;  // P2PKH mainnet
        w.paycode.prefix_bits = prefix_bits;
        w.paycode.expiry      = 0;  // no expiry

        // scan pubkey
        auto spk = secp256k1::ct::generator_mul(w.scan_privkey).to_compressed();
        std::memcpy(w.paycode.scan_pubkey.data(), spk.data(), 33);

        // spend pubkey
        auto spepk = secp256k1::ct::generator_mul(w.spend_privkey).to_compressed();
        std::memcpy(w.paycode.spend_pubkey.data(), spepk.data(), 33);

        w.paycode_str = rpa_encode_paycode(w.paycode);
        return w;
    }
};

// ── Step 2: Sender creates payment ───────────────────────────────────────────

struct SenderPayment {
    GrindResult grind;             // winning signature + input hash
    std::array<uint8_t, 33> output_pubkey;  // send BCH to this address
    std::string output_cashaddr;
    std::array<uint8_t, 32> shared_secret_value;
};

static SenderPayment create_payment(
    const RpaPaycode& paycode,
    const Scalar& sender_input_privkey,
    const std::array<uint8_t, 32>& txid,
    uint32_t vout)
{
    // Outpoint bytes: txid || vout (LE)
    uint8_t outpoint[36];
    std::memcpy(outpoint, txid.data(), 32);
    outpoint[32] = vout & 0xff;
    outpoint[33] = (vout >> 8) & 0xff;
    outpoint[34] = (vout >> 16) & 0xff;
    outpoint[35] = (vout >> 24) & 0xff;

    // a. Compute shared secret: c = SHA256(SHA256(e·Q) || outpoint)
    auto secret = rpa_sender_shared_secret(
        sender_input_privkey,
        paycode.scan_pubkey.data(),
        outpoint, sizeof(outpoint));

    // b. Derive payment pubkey: CKDpub(spend_pubkey, c, 0)
    auto output_pk = rpa_derive_payment_pubkey(
        paycode.spend_pubkey.data(), secret, 0);

    // c. Grind signature until SHA256(SHA256(sig)) prefix matches paycode
    printf("  Grinding signature (prefix=%d bits)...\n", paycode.prefix_bits);
    std::array<uint8_t, 32> msg{};
    msg[31] = 0x01;  // simplified: real wallets use SIGHASH

    uint32_t n_attempts = 0;
    auto on_progress = [&](uint32_t nonce) {
        n_attempts = nonce;
        if (nonce % 10000 == 0 && nonce > 0)
            printf("    ... %u attempts\n", nonce);
    };

    auto grind = rpa_grind_cpu(
        sender_input_privkey,
        msg.data(),
        paycode.prefix_bits,
        paycode.scan_pubkey.data(),
        500000,       // max_tries
        on_progress);

    SenderPayment p;
    p.grind = grind;
    p.output_pubkey = output_pk;
    p.output_cashaddr = cashaddr_from_pubkey(output_pk.data());
    p.shared_secret_value = secret.value;

    secp256k1::detail::secure_erase(&secret, sizeof(secret));
    return p;
}

// ── Step 3: Receiver scans and finds payment ──────────────────────────────────

static void scan_for_payment(
    const ReceiverWallet& receiver,
    const SenderPayment& payment,
    const std::array<uint8_t, 33>& sender_input_pubkey,
    const std::array<uint8_t, 32>& txid,
    uint32_t vout)
{
    RpaScanner scanner(receiver.paycode, receiver.scan_privkey);

    // Build a fake transaction for scanning
    ScanTx tx;
    tx.txid = txid;
    tx.vout = vout;
    tx.input_pubkey = sender_input_pubkey;
    tx.outputs.push_back(payment.output_pubkey);

    printf("  Scanning transaction...\n");
    auto match = scanner.scan_tx(tx, 30);

    if (match) {
        printf("  ✅ FOUND payment!\n");
        printf("  %-24s: %s\n", "CashAddr", match->cashaddr.c_str());
        printf("  %-24s: output %u, key_index %u\n",
               "Position", match->output_index, match->key_index);
    } else {
        printf("  ❌ No match found\n");
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main() {
    printf("============================================================\n");
    printf("  BCH Reusable Payment Addresses — End-to-End Example\n");
    printf("============================================================\n\n");

    // 1. Receiver generates paycode
    printf("[1] Receiver generates paycode (8-bit prefix filter)\n");
    auto receiver = ReceiverWallet::generate(/*prefix_bits=*/8);
    printf("  Paycode: %s\n", receiver.paycode_str.c_str());
    print_hex("Scan pubkey", receiver.paycode.scan_pubkey.data(), 33);
    print_hex("Spend pubkey", receiver.paycode.spend_pubkey.data(), 33);
    printf("  → Publish this paycode. Anyone can send BCH to it.\n\n");

    // 2. Sender creates payment
    printf("[2] Sender creates payment\n");
    auto sender_sk = make_privkey(0x5E4DE28u);
    auto sender_pk = secp256k1::ct::generator_mul(sender_sk).to_compressed();

    std::array<uint8_t, 32> fake_txid{};
    fake_txid[0] = 0xde; fake_txid[1] = 0xad; fake_txid[2] = 0xbe; fake_txid[3] = 0xef;

    auto payment = create_payment(receiver.paycode, sender_sk, fake_txid, 0);

    if (payment.grind.found) {
        printf("  ✅ Signature found after %u attempts\n", payment.grind.nonce);
        print_hex("Input hash prefix", payment.grind.input_hash.data(), 2);
        print_hex("Output pubkey", payment.output_pubkey.data(), 33);
        printf("  CashAddr: %s\n", payment.output_cashaddr.c_str());
        printf("  → Broadcast tx with this input signature.\n\n");
    } else {
        printf("  ❌ Grind failed (max_tries exceeded)\n\n");
        return 1;
    }

    // 3. Receiver scans
    printf("[3] Receiver scans blockchain\n");
    std::array<uint8_t, 33> sender_pk_arr{};
    std::memcpy(sender_pk_arr.data(), sender_pk.data(), 33);
    scan_for_payment(receiver, payment, sender_pk_arr, fake_txid, 0);

    printf("\n============================================================\n");
    printf("  RPA protocol complete.\n");
    printf("  Sender paid to a fresh address — receiver's identity hidden.\n");
    printf("  Receiver detected payment with one ECDH + SHA256 per tx.\n");
    printf("============================================================\n");

    secp256k1::detail::secure_erase(&sender_sk, sizeof(sender_sk));
    secp256k1::detail::secure_erase(&receiver, sizeof(receiver));
    return 0;
}
