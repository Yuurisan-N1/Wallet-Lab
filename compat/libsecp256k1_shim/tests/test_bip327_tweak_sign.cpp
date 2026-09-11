/**
 * test_bip327_tweak_sign.cpp — MuSig2 tweak correctness (BIP-327).
 *
 * Guards the fix for the confirmed P1 bug "MuSig2 tweaked signing broken": the
 * keyagg cache now carries BIP-327 gacc/tacc so that (a) the tweaked aggregate
 * public key is correct and (b) the aggregated signature verifies against it.
 *
 * Two layers:
 *   1. Reference KATs — aggregate of the bip-0327 tweak-vector keys [1,2,0] and the
 *      ordinary (EC) / x-only tweaks by tweaks[0] equal the values produced by the
 *      official bip-0327 reference.py (independent oracle).
 *   2. Full sign+verify roundtrips (no-tweak / EC / x-only / mixed) on an odd-Y
 *      aggregate — every aggregated signature must verify against the tweaked key.
 *
 * Standalone:
 *   g++ -std=c++17 -I ../compat/libsecp256k1_shim/include -I ../src/cpu/include \
 *       test_bip327_tweak_sign.cpp -lufsecp -o t && ./t
 */
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
    for(size_t i=0;i+1<n;i+=2){ auto d=[&](char c)->int{ return c<='9'?c-'0':(c|32)-'a'+10; };
        v.push_back((uint8_t)((d(s[i])<<4)|d(s[i+1]))); }
    return v;
}
static bool eqx(secp256k1_context* ctx, const secp256k1_pubkey* p, const char* expect_hex){
    secp256k1_xonly_pubkey x; int par; secp256k1_xonly_pubkey_from_pubkey(ctx,&x,&par,p);
    uint8_t got[32]; secp256k1_xonly_pubkey_serialize(ctx,got,&x);
    auto e=hx(expect_hex); return e.size()==32 && std::memcmp(got,e.data(),32)==0;
}

// ---- Layer 1: reference KATs (bip-0327 reference.py oracle) ----
static void kats(secp256k1_context* ctx){
    // tweak-vector pubkey set, aggregated in order [1,2,0]
    const char* K[3]={
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"};
    const char* TWEAK="E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB";
    const char* AGG_X  ="e2e14a303b7adeeaae81e72e9f26f75fb43102011b3803198351b48c82956c1f";
    const char* EC_X   ="c7a4356ba33438b49ef0141e9f00eb8146d21ca1e4fcd7f7fecefac2ba4943de";
    const char* XONLY_X="643547cfd6c931f47fe806570e44ffc2460d77057e1506b2b7a1ab73b7f07dfe";

    secp256k1_pubkey p[3]; const secp256k1_pubkey* pp[3];
    for(int i=0;i<3;++i){ auto b=hx(K[i]); secp256k1_ec_pubkey_parse(ctx,&p[i],b.data(),33); pp[i]=&p[i]; }
    auto tw=hx(TWEAK);

    // Each cache is token-keyed (aliased on copy), so re-aggregate fresh for each check.
    { secp256k1_xonly_pubkey agg; secp256k1_musig_keyagg_cache c;
      CHECK(secp256k1_musig_pubkey_agg(ctx,&agg,&c,pp,3)==1, "keyagg [1,2,0] succeeds");
      uint8_t ax[32]; secp256k1_xonly_pubkey_serialize(ctx,ax,&agg); auto e=hx(AGG_X);
      CHECK(std::memcmp(ax,e.data(),32)==0, "aggregate == reference.py oracle"); }

    { secp256k1_xonly_pubkey agg; secp256k1_musig_keyagg_cache c; secp256k1_pubkey o;
      secp256k1_musig_pubkey_agg(ctx,&agg,&c,pp,3);
      CHECK(secp256k1_musig_pubkey_ec_tweak_add(ctx,&o,&c,tw.data())==1, "ec_tweak_add succeeds");
      CHECK(eqx(ctx,&o,EC_X), "EC-tweaked output == reference.py oracle (was the bug)"); }
    { secp256k1_xonly_pubkey agg; secp256k1_musig_keyagg_cache c; secp256k1_pubkey o;
      secp256k1_musig_pubkey_agg(ctx,&agg,&c,pp,3);
      CHECK(secp256k1_musig_pubkey_xonly_tweak_add(ctx,&o,&c,tw.data())==1, "xonly_tweak_add succeeds");
      CHECK(eqx(ctx,&o,XONLY_X), "x-only-tweaked output == reference.py oracle"); }
}

// ---- Layer 2: full sign+verify roundtrip ----
static int roundtrip(secp256k1_context* ctx, int mode /*0 none,1 ec,2 xonly,3 mixed*/){
    const int N=3;
    unsigned char sk[N][32]; secp256k1_pubkey pub[N]; secp256k1_keypair kp[N];
    for(int i=0;i<N;++i){ std::memset(sk[i],0,32); sk[i][31]=(unsigned char)(7*i+3); sk[i][20]=(unsigned char)(i+1);
        if(!secp256k1_keypair_create(ctx,&kp[i],sk[i])) return -1;
        if(!secp256k1_keypair_pub(ctx,&pub[i],&kp[i])) return -1; }
    const secp256k1_pubkey* pp[N]={&pub[0],&pub[1],&pub[2]};
    secp256k1_xonly_pubkey agg; secp256k1_musig_keyagg_cache cache;
    if(!secp256k1_musig_pubkey_agg(ctx,&agg,&cache,pp,N)) return -1;

    unsigned char tw[32]; std::memset(tw,0,32); tw[31]=0x07; tw[0]=0x11;
    unsigned char tw2[32]; std::memset(tw2,0,32); tw2[31]=0x21; tw2[5]=0x9a;
    secp256k1_pubkey o;
    if(mode==1){ if(!secp256k1_musig_pubkey_ec_tweak_add(ctx,&o,&cache,tw)) return -1; }
    else if(mode==2){ if(!secp256k1_musig_pubkey_xonly_tweak_add(ctx,&o,&cache,tw)) return -1; }
    else if(mode==3){ if(!secp256k1_musig_pubkey_ec_tweak_add(ctx,&o,&cache,tw)) return -1;
                      if(!secp256k1_musig_pubkey_xonly_tweak_add(ctx,&o,&cache,tw2)) return -1; }

    secp256k1_pubkey tfull; secp256k1_musig_pubkey_get(ctx,&tfull,&cache);
    secp256k1_xonly_pubkey tx; int tpar; secp256k1_xonly_pubkey_from_pubkey(ctx,&tx,&tpar,&tfull);

    unsigned char msg[32]; for(int i=0;i<32;++i) msg[i]=(unsigned char)(0xA0+i);
    secp256k1_musig_secnonce sn[N]; secp256k1_musig_pubnonce pn[N];
    for(int i=0;i<N;++i){ unsigned char sid[32]; std::memset(sid,0,32); sid[0]=(unsigned char)(0x40+i); sid[31]=(unsigned char)(mode+1);
        if(!secp256k1_musig_nonce_gen(ctx,&sn[i],&pn[i],sid,sk[i],&pub[i],msg,&cache,nullptr)) return -1; }
    const secp256k1_musig_pubnonce* pnp[N]={&pn[0],&pn[1],&pn[2]};
    secp256k1_musig_aggnonce an; if(!secp256k1_musig_nonce_agg(ctx,&an,pnp,N)) return -1;
    secp256k1_musig_session sess; if(!secp256k1_musig_nonce_process(ctx,&sess,&an,msg,&cache)) return -1;
    secp256k1_musig_partial_sig ps[N];
    for(int i=0;i<N;++i){ if(!secp256k1_musig_partial_sign(ctx,&ps[i],&sn[i],&kp[i],&cache,&sess)) return -1; }
    // each partial sig must also pass per-signer verification (covers gacc in partial_verify)
    for(int i=0;i<N;++i){ if(!secp256k1_musig_partial_sig_verify(ctx,&ps[i],&pn[i],&pub[i],&cache,&sess)) return 0; }
    const secp256k1_musig_partial_sig* psp[N]={&ps[0],&ps[1],&ps[2]};
    unsigned char sig[64]; if(!secp256k1_musig_partial_sig_agg(ctx,sig,&sess,psp,N)) return -1;
    return secp256k1_schnorrsig_verify(ctx,sig,msg,32,&tx) ? 1 : 0;
}

int main(){
    secp256k1_context* ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
    std::printf("== BIP-327 MuSig2 tweak correctness (output KATs + sign/verify) ==\n");
    kats(ctx);
    CHECK(roundtrip(ctx,0)==1, "roundtrip no-tweak: aggregated sig verifies");
    CHECK(roundtrip(ctx,1)==1, "roundtrip EC-tweak: aggregated sig verifies (was the bug)");
    CHECK(roundtrip(ctx,2)==1, "roundtrip x-only-tweak: aggregated sig verifies (was the bug)");
    CHECK(roundtrip(ctx,3)==1, "roundtrip mixed EC+x-only tweaks: aggregated sig verifies");
    secp256k1_context_destroy(ctx);
    std::printf("\n%s\n", g_fail==0?"ALL PASS":"FAILURES PRESENT");
    return g_fail==0?0:1;
}
