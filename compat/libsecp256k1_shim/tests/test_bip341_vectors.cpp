/**
 * test_bip341_vectors.cpp — official BIP-341 Taproot key-path tweak vectors.
 *
 * keyPathSpending cases from bitcoin/bips bip-0341/wallet-test-vectors.json:
 * given (internalPubkey, tweak) the derived output key must equal tweakedPubkey.
 * Exercises the libsecp256k1 drop-in shim's consensus-critical Taproot tweak path
 *   - secp256k1_xonly_pubkey_tweak_add  (derive output key Q = lift_x(P) + tweak*G),
 *   - secp256k1_xonly_pubkey_tweak_add_check  (the commitment check our GPU/CPU
 *     batch endpoints accelerate) — both must agree with the canonical vector.
 *
 * Standalone:
 *   g++ -std=c++17 -I ../compat/libsecp256k1_shim/include -I ../src/cpu/include \
 *       test_bip341_vectors.cpp -lufsecp -o t && ./t
 */
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

static int g_fail = 0;
#define CHECK(cond, msg) do { if(!(cond)){ std::printf("  FAIL: %s\n", msg); ++g_fail; } \
                              else { std::printf("  ok  : %s\n", msg); } } while(0)

static std::vector<uint8_t> hx(const char* s){
    std::vector<uint8_t> v; if(!s) return v; size_t n=std::strlen(s);
    for(size_t i=0;i+1<n;i+=2){ auto d=[&](char c)->int{ return c<='9'?c-'0':(c|32)-'a'+10; };
        v.push_back((uint8_t)((d(s[i])<<4)|d(s[i+1]))); }
    return v;
}

struct Vec { const char* internal; const char* tweak; const char* tweaked; };

// bitcoin/bips bip-0341/wallet-test-vectors.json  (keyPathSpending intermediary)
static const Vec VS[] = {
{"d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d","b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70","53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"},
{"187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27","cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001","147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3"},
{"93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820","6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30","e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e"},
{"e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f","b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4","91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605"},
{"55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d","6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9","75169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831"},
{"ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592","9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9","712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5"},
{"f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8","639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e","77e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220"},
};

int main(){
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if(!ctx){ std::printf("ctx fail\n"); return 1; }
    int n = (int)(sizeof(VS)/sizeof(VS[0]));
    std::printf("== BIP-341 Taproot key-path tweak vectors via libsecp shim (%d) ==\n", n);

    for(int i=0;i<n;++i){
        auto ip=hx(VS[i].internal), tw=hx(VS[i].tweak), exp=hx(VS[i].tweaked);
        char nm[128];
        std::snprintf(nm,sizeof(nm),"vec %d well-formed (32/32/32)", i);
        CHECK(ip.size()==32 && tw.size()==32 && exp.size()==32, nm);
        if(ip.size()!=32 || tw.size()!=32 || exp.size()!=32) continue;

        secp256k1_xonly_pubkey internal;
        int pok = secp256k1_xonly_pubkey_parse(ctx, &internal, ip.data());
        std::snprintf(nm,sizeof(nm),"vec %d internal pubkey parses", i);
        CHECK(pok==1, nm); if(!pok) continue;

        // derive Q = lift_x(P) + tweak*G, get its x-only + parity
        secp256k1_pubkey out;
        int tok = secp256k1_xonly_pubkey_tweak_add(ctx, &out, &internal, tw.data());
        std::snprintf(nm,sizeof(nm),"vec %d tweak_add succeeds", i);
        CHECK(tok==1, nm); if(!tok) continue;

        secp256k1_xonly_pubkey outx; int parity=0;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &outx, &parity, &out);
        uint8_t got[32]; secp256k1_xonly_pubkey_serialize(ctx, got, &outx);
        std::snprintf(nm,sizeof(nm),"vec %d derived output key == canonical tweakedPubkey", i);
        CHECK(std::memcmp(got, exp.data(), 32)==0, nm);

        // the commitment check (basis of our batch endpoints) must accept it
        int chk = secp256k1_xonly_pubkey_tweak_add_check(ctx, exp.data(), parity, &internal, tw.data());
        std::snprintf(nm,sizeof(nm),"vec %d tweak_add_check accepts canonical output+parity", i);
        CHECK(chk==1, nm);
    }

    secp256k1_context_destroy(ctx);
    std::printf("\n%s\n", g_fail==0?"ALL PASS":"FAILURES PRESENT");
    return g_fail==0?0:1;
}
