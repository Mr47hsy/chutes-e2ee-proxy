/*
 * selftest.c - offline verification of libe2ee_proxy primitives.
 *
 * Built and executed by native/build.sh --selftest, which the Docker build
 * runs as a gate. Every check here is against a published vector or a
 * property that must hold for the Chutes wire format:
 *
 *   ML-KEM-768        NIST ACVP FIPS 203 KATs (keyGen, encaps, decaps, implicit
 *                     rejection). These pass ONLY for FIPS 203 ML-KEM; a Kyber
 *                     round-3 build fails them by design.
 *   HKDF-SHA256       RFC 5869 A.1-A.3
 *   ChaCha20          RFC 8439 2.4.2 keystream (through the seal path)
 *   AEAD (no AAD)     Wycheproof chacha20_poly1305 empty-AAD cases + tamper checks
 *   gzip              round-trip, framing, garbage rejection
 *   random            basic sanity
 *
 * What this cannot prove: that Chutes' instances speak the same ML-KEM
 * variant. Only a real end-to-end request proves that (README).
 */
#include "e2ee_proxy_api.h"
#include "mlkem_backend.h"
#include "selftest_kat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { \
        failures++; \
        fprintf(stderr, "  FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
    } \
} while (0)

static void hexdump_prefix(const char *label, const uint8_t *b, size_t n) {
    fprintf(stderr, "    %s=", label);
    for (size_t i = 0; i < n && i < 16; i++) fprintf(stderr, "%02x", b[i]);
    fprintf(stderr, "%s\n", n > 16 ? "..." : "");
}

/* ------------------------------------------------------------------------- */

static void test_mlkem_sizes_and_roundtrip(void) {
    printf("[mlkem] backend: %s\n", E2EE_MLKEM_BACKEND_NAME);
    CHECK(E2EE_MLKEM_PK_SIZE == 1184 && E2EE_MLKEM_SK_SIZE == 2400 &&
          E2EE_MLKEM_CT_SIZE == 1088 && E2EE_MLKEM_SS_SIZE == 32, "size constants");

    for (int i = 0; i < 10; i++) {
        uint8_t pk[E2EE_MLKEM_PK_SIZE], sk[E2EE_MLKEM_SK_SIZE];
        uint8_t ct[E2EE_MLKEM_CT_SIZE], ss1[32], ss2[32];
        CHECK(e2ee_mlkem_keygen(pk, sk) == 0, "keygen rc");
        CHECK(e2ee_mlkem_encapsulate(pk, ct, ss1) == 0, "encaps rc");
        CHECK(e2ee_mlkem_decapsulate(sk, ct, ss2) == 0, "decaps rc");
        CHECK(memcmp(ss1, ss2, 32) == 0, "round-trip shared secret mismatch (iter %d)", i);

        /* Tampered ciphertext must yield a different (implicit-rejection) secret. */
        uint8_t bad[E2EE_MLKEM_CT_SIZE];
        memcpy(bad, ct, sizeof bad);
        bad[i * 97 % E2EE_MLKEM_CT_SIZE] ^= 0x01;
        uint8_t ss3[32];
        CHECK(e2ee_mlkem_decapsulate(sk, bad, ss3) == 0, "decaps(bad) rc");
        CHECK(memcmp(ss1, ss3, 32) != 0, "tampered ct produced the same secret (iter %d)", i);
    }
    /* Two keygens must differ (RNG actually wired in). */
    uint8_t pk1[E2EE_MLKEM_PK_SIZE], sk1[E2EE_MLKEM_SK_SIZE];
    uint8_t pk2[E2EE_MLKEM_PK_SIZE], sk2[E2EE_MLKEM_SK_SIZE];
    e2ee_mlkem_keygen(pk1, sk1);
    e2ee_mlkem_keygen(pk2, sk2);
    CHECK(memcmp(pk1, pk2, sizeof pk1) != 0, "two keygens produced identical pk");
}

static void test_mlkem_kat(void) {
#if E2EE_MLKEM_HAS_DERAND
    printf("[mlkem] NIST ACVP FIPS 203 KATs (keyGen vsId=%d, encapDecap vsId=%d)\n",
           KAT_ACVP_KEYGEN_VSID, KAT_ACVP_ENCAPDECAP_VSID);

    /* keyGen: coins = d || z */
    {
        uint8_t coins[64], pk[E2EE_MLKEM_PK_SIZE], sk[E2EE_MLKEM_SK_SIZE];
        memcpy(coins, KAT_KEYGEN_D, 32);
        memcpy(coins + 32, KAT_KEYGEN_Z, 32);
        CHECK(mlkem_keypair_derand(pk, sk, coins) == 0, "keypair_derand rc");
        CHECK(memcmp(pk, KAT_KEYGEN_EK, E2EE_MLKEM_PK_SIZE) == 0, "keyGen KAT: ek mismatch");
        CHECK(memcmp(sk, KAT_KEYGEN_DK, E2EE_MLKEM_SK_SIZE) == 0, "keyGen KAT: dk mismatch");
    }
    /* encaps: coins = m */
    {
        uint8_t ct[E2EE_MLKEM_CT_SIZE], ss[32];
        CHECK(mlkem_enc_derand(ct, ss, KAT_ENCAP_EK, KAT_ENCAP_M) == 0, "enc_derand rc");
        CHECK(memcmp(ct, KAT_ENCAP_C, E2EE_MLKEM_CT_SIZE) == 0, "encaps KAT: ciphertext mismatch");
        CHECK(memcmp(ss, KAT_ENCAP_K, 32) == 0, "encaps KAT: shared secret mismatch");
        if (memcmp(ss, KAT_ENCAP_K, 32) != 0) {
            hexdump_prefix("got ", ss, 32);
            hexdump_prefix("want", KAT_ENCAP_K, 32);
        }
        /* and the public decaps path recovers it */
        uint8_t ss2[32];
        CHECK(e2ee_mlkem_decapsulate(KAT_ENCAP_DK, KAT_ENCAP_C, ss2) == 0, "decaps rc");
        CHECK(memcmp(ss2, KAT_ENCAP_K, 32) == 0, "decaps of KAT ciphertext mismatch");
    }
    /* decaps: valid */
    {
        uint8_t ss[32];
        CHECK(e2ee_mlkem_decapsulate(KAT_DECAP_VALID_DK, KAT_DECAP_VALID_C, ss) == 0, "decaps rc");
        CHECK(memcmp(ss, KAT_DECAP_VALID_K, 32) == 0, "decaps KAT (valid): mismatch");
    }
    /* decaps: modified ciphertext -> implicit rejection value must match FIPS 203 J(z||c) */
    {
        uint8_t ss[32];
        CHECK(e2ee_mlkem_decapsulate(KAT_DECAP_REJECT_DK, KAT_DECAP_REJECT_C, ss) == 0, "decaps rc");
        CHECK(memcmp(ss, KAT_DECAP_REJECT_K, 32) == 0,
              "decaps KAT (implicit rejection): mismatch -- not FIPS 203 behaviour");
    }
#else
    printf("[mlkem] backend has no deterministic API; NIST FIPS 203 KATs skipped "
           "(this backend is NOT FIPS 203 and will not interoperate with a FIPS 203 peer)\n");
#endif
}

/* ------------------------------------------------------------------------- */

static void test_hkdf(void) {
    printf("[hkdf] RFC 5869 SHA-256 cases: %zu\n", (size_t)HKDF_CASES_N);
    for (size_t i = 0; i < HKDF_CASES_N; i++) {
        const hkdf_case_t *c = &HKDF_CASES[i];
        uint8_t okm[256];
        int rc = e2ee_hkdf_sha256(c->ikm, c->ikm_len,
                                  c->salt_len ? c->salt : NULL, c->salt_len,
                                  c->info_len ? c->info : NULL, c->info_len,
                                  okm, c->okm_len);
        CHECK(rc == 0, "%s: rc=%d", c->name, rc);
        CHECK(memcmp(okm, c->okm, c->okm_len) == 0, "%s: OKM mismatch", c->name);
    }
    /* Shape used by the protocol: 32-byte ss, 16-byte salt, ascii info, 32-byte key. */
    {
        uint8_t ss[32], salt[16], key1[32], key2[32];
        e2ee_random_bytes(ss, 32);
        e2ee_random_bytes(salt, 16);
        CHECK(e2ee_hkdf_sha256(ss, 32, salt, 16, (const uint8_t *)"e2e-req-v1", 10, key1, 32) == 0, "protocol hkdf");
        CHECK(e2ee_hkdf_sha256(ss, 32, salt, 16, (const uint8_t *)"e2e-resp-v1", 11, key2, 32) == 0, "protocol hkdf");
        CHECK(memcmp(key1, key2, 32) != 0, "req/resp keys must differ (domain separation)");
        CHECK(e2ee_hkdf_sha256(ss, 32, salt, 16, (const uint8_t *)"x", 1, key1, 255 * 32 + 1) != 0,
              "must reject okm_len > 255*HashLen");
    }
}

/* ------------------------------------------------------------------------- */

static void test_chacha20_rfc8439(void) {
    printf("[aead] RFC 8439 2.4.2 keystream via seal (%zu bytes)\n", (size_t)KAT_RFC8439_PT_LEN);
    uint8_t ct[KAT_RFC8439_PT_LEN], tag[16];
    CHECK(e2ee_chacha20_seal(KAT_RFC8439_KEY, KAT_RFC8439_NONCE,
                             KAT_RFC8439_PT, KAT_RFC8439_PT_LEN, ct, tag) == 0, "seal rc");
    CHECK(memcmp(ct, KAT_RFC8439_CT, KAT_RFC8439_PT_LEN) == 0,
          "ChaCha20 keystream mismatch (wrong counter or nonce handling)");
    uint8_t pt[KAT_RFC8439_PT_LEN];
    CHECK(e2ee_chacha20_open(KAT_RFC8439_KEY, KAT_RFC8439_NONCE, ct, sizeof ct, tag, pt) == 0, "open rc");
    CHECK(memcmp(pt, KAT_RFC8439_PT, sizeof pt) == 0, "open plaintext mismatch");
}

static void test_aead_wycheproof(void) {
    printf("[aead] Wycheproof chacha20_poly1305 empty-AAD cases: %zu\n", (size_t)AEAD_CASES_N);
    for (size_t i = 0; i < AEAD_CASES_N; i++) {
        const aead_case_t *c = &AEAD_CASES[i];
        uint8_t *ct = malloc(c->msg_len + 1);
        uint8_t *pt = malloc(c->msg_len + 1);
        uint8_t tag[16];

        CHECK(e2ee_chacha20_seal(c->key, c->iv, c->msg, c->msg_len, ct, tag) == 0, "tc%d seal rc", c->tcId);
        CHECK(memcmp(ct, c->ct, c->msg_len) == 0, "tc%d ciphertext mismatch", c->tcId);
        CHECK(memcmp(tag, c->tag, 16) == 0, "tc%d tag mismatch", c->tcId);

        CHECK(e2ee_chacha20_open(c->key, c->iv, c->ct, c->msg_len, c->tag, pt) == 0, "tc%d open rc", c->tcId);
        CHECK(memcmp(pt, c->msg, c->msg_len) == 0, "tc%d plaintext mismatch", c->tcId);

        /* tamper: tag bit flip */
        uint8_t badtag[16];
        memcpy(badtag, c->tag, 16);
        badtag[i % 16] ^= 0x80;
        CHECK(e2ee_chacha20_open(c->key, c->iv, c->ct, c->msg_len, badtag, pt) != 0,
              "tc%d accepted a corrupted tag", c->tcId);

        /* tamper: ciphertext bit flip (only when there is ciphertext) */
        if (c->msg_len > 0) {
            memcpy(ct, c->ct, c->msg_len);
            ct[c->msg_len / 2] ^= 0x01;
            CHECK(e2ee_chacha20_open(c->key, c->iv, ct, c->msg_len, c->tag, pt) != 0,
                  "tc%d accepted corrupted ciphertext", c->tcId);
            /* and the output was scrubbed */
            int allzero = 1;
            for (size_t k = 0; k < c->msg_len; k++) if (pt[k]) { allzero = 0; break; }
            CHECK(allzero, "tc%d leaked plaintext on auth failure", c->tcId);
        }
        /* nonce change must fail */
        uint8_t badiv[12];
        memcpy(badiv, c->iv, 12);
        badiv[0] ^= 0x01;
        CHECK(e2ee_chacha20_open(c->key, badiv, c->ct, c->msg_len, c->tag, pt) != 0,
              "tc%d accepted wrong nonce", c->tcId);
        free(ct);
        free(pt);
    }
    /* large in-place style buffer (1 MiB) round-trips */
    {
        size_t n = 1u << 20;
        uint8_t *buf = malloc(n), *ct = malloc(n), *pt = malloc(n);
        uint8_t key[32], nonce[12], tag[16];
        e2ee_random_bytes(key, 32);
        e2ee_random_bytes(nonce, 12);
        for (size_t k = 0; k < n; k++) buf[k] = (uint8_t)(k * 31u);
        CHECK(e2ee_chacha20_seal(key, nonce, buf, n, ct, tag) == 0, "1MiB seal");
        CHECK(e2ee_chacha20_open(key, nonce, ct, n, tag, pt) == 0, "1MiB open");
        CHECK(memcmp(buf, pt, n) == 0, "1MiB round-trip");
        free(buf); free(ct); free(pt);
    }
}

/* ------------------------------------------------------------------------- */

static void test_gzip(void) {
    printf("[gzip] round-trip / framing\n");
    const char *msg = "{\"model\":\"x\",\"messages\":[{\"role\":\"user\",\"content\":\"hello hello hello\"}]}";
    size_t n = strlen(msg);
    uint8_t comp[4096], decomp[4096];
    size_t clen = e2ee_gzip_compress((const uint8_t *)msg, n, comp, sizeof comp);
    CHECK(clen > 0, "compress failed");
    CHECK(clen >= 18 && comp[0] == 0x1f && comp[1] == 0x8b, "output is not gzip-framed (got %02x%02x)", comp[0], comp[1]);
    /* ISIZE trailer = uncompressed length (the Lua side relies on this to size buffers) */
    if (clen >= 4) {
        uint32_t isize = (uint32_t)comp[clen - 4] | ((uint32_t)comp[clen - 3] << 8)
                       | ((uint32_t)comp[clen - 2] << 16) | ((uint32_t)comp[clen - 1] << 24);
        CHECK(isize == n, "gzip ISIZE trailer %u != %zu", isize, n);
    }
    size_t dlen = e2ee_gzip_decompress(comp, clen, decomp, sizeof decomp);
    CHECK(dlen == n, "decompress length %zu != %zu", dlen, n);
    CHECK(dlen == n && memcmp(decomp, msg, n) == 0, "decompress content mismatch");

    /* Output buffer too small must fail cleanly, not truncate. */
    CHECK(e2ee_gzip_decompress(comp, clen, decomp, 8) == 0, "undersized output accepted");
    CHECK(e2ee_gzip_compress((const uint8_t *)msg, n, comp, 4) == 0, "undersized compress output accepted");

    /* Garbage rejected. */
    uint8_t junk[64];
    e2ee_random_bytes(junk, sizeof junk);
    junk[0] = 0x00;
    CHECK(e2ee_gzip_decompress(junk, sizeof junk, decomp, sizeof decomp) == 0, "garbage decompressed");

    /* Incompressible payload (simulates base64 image) with a deflateBound-ish buffer. */
    {
        size_t big = 512 * 1024;
        uint8_t *in = malloc(big);
        e2ee_random_bytes(in, big);
        size_t bound = big + (big >> 12) + (big >> 14) + (big >> 25) + 64;
        uint8_t *out = malloc(bound);
        size_t got = e2ee_gzip_compress(in, big, out, bound);
        CHECK(got > 0, "incompressible 512KiB failed within bound %zu", bound);
        uint8_t *back = malloc(big);
        CHECK(e2ee_gzip_decompress(out, got, back, big) == big, "incompressible round-trip len");
        CHECK(memcmp(in, back, big) == 0, "incompressible round-trip content");
        free(in); free(out); free(back);
    }
    /* Empty input compresses to a valid empty gzip member. */
    {
        size_t got = e2ee_gzip_compress((const uint8_t *)"", 0, comp, sizeof comp);
        CHECK(got > 0, "empty compress");
        /* empty decompress is defined as failure (0) by our API; ensure no crash */
        (void)e2ee_gzip_decompress(comp, got, decomp, sizeof decomp);
    }
}

/* ------------------------------------------------------------------------- */

static void test_random_and_stubs(void) {
    printf("[misc] random / init / cert stubs\n");
    uint8_t a[32] = {0}, b[32] = {0};
    e2ee_random_bytes(a, 32);
    e2ee_random_bytes(b, 32);
    CHECK(memcmp(a, b, 32) != 0, "two random draws identical");
    int nz = 0;
    for (int i = 0; i < 32; i++) nz |= a[i];
    CHECK(nz != 0, "random draw all zero");

    CHECK(e2ee_init() == 0, "init");
    CHECK(e2ee_build_info() != NULL && strstr(e2ee_build_info(), "mlkem=") != NULL, "build info");

    uint8_t buf[8];
    size_t len = sizeof buf;
    CHECK(e2ee_get_cert_der(buf, &len) != 0 && len == 0, "cert stub must fail with len=0");
    len = sizeof buf;
    CHECK(e2ee_get_privkey_der(buf, &len) != 0 && len == 0, "privkey stub must fail with len=0");
}

/* ------------------------------------------------------------------------- */

int main(void) {
    printf("=== libe2ee_proxy self-test ===\n%s\n", e2ee_build_info());
    test_mlkem_sizes_and_roundtrip();
    test_mlkem_kat();
    test_hkdf();
    test_chacha20_rfc8439();
    test_aead_wycheproof();
    test_gzip();
    test_random_and_stubs();
    printf("=== %d checks, %d failures ===\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
