// ============================================================================
// test_bip327_sign_verify_vectors.cpp
// Official BIP-327 sign_verify_vectors.json — VERIFY side conformance.
//
// Source: github.com/bitcoin/bips/bip-0327/vectors/sign_verify_vectors.json
//
// Guards the MuSig2 binding-factor tag ("MuSig/noncecoef") and the partial-sig
// verification path against the canonical BIP-327 data, INDEPENDENT of the
// engine's own signing (the partial sigs are produced by the reference impl).
// This is the regression guard for the confirmed interop bug where the engine
// used a non-standard binding tag ("MuSig/nonceblinding") — self-consistent for
// pure-engine sessions but rejecting every externally-produced partial sig.
//
// Coverage (verify side only — the C API has no raw secnonce parser, so the SIGN
// side of these vectors cannot be driven through the public API):
//   * every valid partial signature must verify against its signer
//   * verify_fail cases must be rejected (well-formed but invalid)
//   * verify_error cases must be rejected at the invalid contribution (parse/agg)
// The official infinity-aggregate-nonce valid case (both halves the point at
// infinity) is verified like any other: the engine substitutes R=G per BIP-327
// §GetSessionValues, so the external partial signature verifies.
//
// Skipped (documented divergence, not a failure):
//   * variable-length messages (empty / 38-byte): the C API is msg32-only,
//     matching upstream libsecp256k1.
//
// Standalone:
//   g++ -std=c++17 -I ../compat/libsecp256k1_shim/include -I ../src/cpu/include \\
//       test_bip327_sign_verify_vectors.cpp -lufsecp -o t && ./t
// ============================================================================
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_musig.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

static int g_fail=0;
#define CHECK(c,m) do{ if(!(c)){ std::printf("  FAIL: %s\n",m); ++g_fail;} else std::printf("  ok  : %s\n",m);}while(0)

static std::vector<uint8_t> hx(const char* s){
    std::vector<uint8_t> v; if(!s) return v; size_t n=std::strlen(s);
    auto d=[](char ch)->int{ return ch<=0x39?ch-0x30:(ch|0x20)-0x61+10; };
    for(size_t i=0;i+1<n;i+=2) v.push_back((uint8_t)((d(s[i])<<4)|d(s[i+1])));
    return v;
}
static const char* PUBKEYS[4] = {
    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661",
    "020000000000000000000000000000000000000000000000000000000000000007"
};
static const char* PNONCES[5] = {
    "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
    "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
    "032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046",
    "0237C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0387BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
    "0200000000000000000000000000000000000000000000000000000000000000090287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
};
static const char* MSG0 = "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF";

struct VCase{ int n; int ki[3]; int ni[3]; int signer; const char* sig; int inf; };
static const VCase VALID[] = {
    { 3, {0,1,2}, {0,1,2}, 0, "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB", 0 },
    { 3, {1,0,2}, {1,0,2}, 1, "9FF2F7AAA856150CC8819254218D3ADEEB0535269051897724F9DB3789513A52", 0 },
    { 3, {1,2,0}, {1,2,0}, 2, "FA23C359F6FAC4E7796BB93BC9F0532A95468C539BA20FF86D7C76ED92227900", 0 },
    { 2, {0,1,0}, {0,3,0}, 0, "AE386064B26105404798F75DE2EB9AF5EDA5387B064B83D049CB7C5E08879531", 1 }
};
static const int N_VALID=4;
static const VCase FAIL[] = {
    { 3, {0,1,2}, {0,1,2}, 0, "FED54434AD4CFE953FC527DC6A5E5BE8F6234907B7C187559557CE87A0541C46", 0 },
    { 3, {0,1,2}, {0,1,2}, 1, "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB", 0 },
    { 3, {0,1,2}, {0,1,2}, 0, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0 }
};
static const int N_FAIL=3;
struct ECase{ int ki[3]; int ni[3]; const char* contrib; const char* comment; };
static const ECase ERR[] = {
    { {0,1,2}, {4,1,2}, "pubnonce", "Invalid pubnonce" },
    { {3,1,2}, {0,1,2}, "pubkey", "Invalid pubkey" }
};
static const int N_ERR=2;
static const int N_SKIP_VARMSG=2;

static bool build_cache(secp256k1_context* ctx,const int* ki,int n,secp256k1_musig_keyagg_cache* cache){
    secp256k1_pubkey pk[3]; const secp256k1_pubkey* pp[3];
    for(int j=0;j<n;++j){ auto b=hx(PUBKEYS[ki[j]]);
        if(!secp256k1_ec_pubkey_parse(ctx,&pk[j],b.data(),b.size())) return false; pp[j]=&pk[j]; }
    secp256k1_xonly_pubkey agg;
    return secp256k1_musig_pubkey_agg(ctx,&agg,cache,pp,n)==1;
}
static bool build_session(secp256k1_context* ctx,const int* ki,const int* ni,int n,
                          const uint8_t* msg32,secp256k1_musig_keyagg_cache* cache,secp256k1_musig_session* sess){
    if(!build_cache(ctx,ki,n,cache)) return false;
    secp256k1_musig_pubnonce pn[3]; const secp256k1_musig_pubnonce* pnp[3];
    for(int j=0;j<n;++j){ auto b=hx(PNONCES[ni[j]]);
        if(b.size()!=66 || !secp256k1_musig_pubnonce_parse(ctx,&pn[j],b.data())) return false; pnp[j]=&pn[j]; }
    secp256k1_musig_aggnonce an;
    if(!secp256k1_musig_nonce_agg(ctx,&an,pnp,n)) return false;
    return secp256k1_musig_nonce_process(ctx,sess,&an,msg32,cache)==1;
}

int main(){
    secp256k1_context* ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
    std::printf("== BIP-327 sign_verify_vectors.json (verify side) ==\n");
    auto m=hx(MSG0); int n_inf=0;

    for(int i=0;i<N_VALID;++i){ const VCase& c=VALID[i];
        secp256k1_musig_keyagg_cache cache; secp256k1_musig_session sess; char msg[110];
        bool oks=build_session(ctx,c.ki,c.ni,c.n,m.data(),&cache,&sess);
        if(c.inf) ++n_inf; // BIP-327 infinity aggnonce (R=G) — now accepted + must verify like any case
        std::snprintf(msg,sizeof msg,"valid[%d] session builds%s",i,c.inf?" (infinity aggnonce -> R=G)":""); CHECK(oks,msg); if(!oks) continue;
        secp256k1_musig_partial_sig ps; auto sb=hx(c.sig);
        bool okp=secp256k1_musig_partial_sig_parse(ctx,&ps,sb.data())==1;
        std::snprintf(msg,sizeof msg,"valid[%d] partial_sig parses",i); CHECK(okp,msg); if(!okp) continue;
        secp256k1_pubkey spk; auto pb=hx(PUBKEYS[c.ki[c.signer]]);
        secp256k1_ec_pubkey_parse(ctx,&spk,pb.data(),pb.size());
        secp256k1_musig_pubnonce spn; auto nb=hx(PNONCES[c.ni[c.signer]]);
        secp256k1_musig_pubnonce_parse(ctx,&spn,nb.data());
        int v=secp256k1_musig_partial_sig_verify(ctx,&ps,&spn,&spk,&cache,&sess);
        std::snprintf(msg,sizeof msg,"valid[%d] partial_sig_verify == 1 (external BIP-327 sig)",i); CHECK(v==1,msg);
    }

    for(int i=0;i<N_FAIL;++i){ const VCase& c=FAIL[i];
        secp256k1_musig_keyagg_cache cache; secp256k1_musig_session sess; char msg[96];
        if(!build_session(ctx,c.ki,c.ni,c.n,m.data(),&cache,&sess)){
            std::snprintf(msg,sizeof msg,"fail[%d] session builds",i); CHECK(false,msg); continue; }
        secp256k1_musig_partial_sig ps; auto sb=hx(c.sig);
        if(!secp256k1_musig_partial_sig_parse(ctx,&ps,sb.data())){
            std::snprintf(msg,sizeof msg,"fail[%d] rejected (parse)",i); CHECK(true,msg); continue; }
        secp256k1_pubkey spk; auto pb=hx(PUBKEYS[c.ki[c.signer]]);
        secp256k1_ec_pubkey_parse(ctx,&spk,pb.data(),pb.size());
        secp256k1_musig_pubnonce spn; auto nb=hx(PNONCES[c.ni[c.signer]]);
        secp256k1_musig_pubnonce_parse(ctx,&spn,nb.data());
        int v=secp256k1_musig_partial_sig_verify(ctx,&ps,&spn,&spk,&cache,&sess);
        std::snprintf(msg,sizeof msg,"fail[%d] partial_sig_verify == 0 (rejected)",i); CHECK(v==0,msg);
    }

    for(int i=0;i<N_ERR;++i){ const ECase& c=ERR[i];
        char msg[128]; bool rejected=false;
        if(std::strcmp(c.contrib,"pubkey")==0){ secp256k1_musig_keyagg_cache cache;
            rejected=!build_cache(ctx,c.ki,3,&cache);
            std::snprintf(msg,sizeof msg,"error[%d] invalid pubkey rejected (%s)",i,c.comment);
        } else { secp256k1_musig_keyagg_cache cache; secp256k1_musig_session sess;
            rejected=!build_session(ctx,c.ki,c.ni,3,m.data(),&cache,&sess);
            std::snprintf(msg,sizeof msg,"error[%d] invalid pubnonce rejected (%s)",i,c.comment); }
        CHECK(rejected,msg);
    }

    std::printf("  note: %d variable-length-message valid case(s) skipped (C API is msg32-only)\n",N_SKIP_VARMSG);
    std::printf("  note: %d infinity-aggnonce valid case(s) verified (BIP-327 R=G conformant)\n",n_inf);
    secp256k1_context_destroy(ctx);
    std::printf("\n%s\n", g_fail==0?"ALL PASS":"FAILURES PRESENT");
    return g_fail==0?0:1;
}
