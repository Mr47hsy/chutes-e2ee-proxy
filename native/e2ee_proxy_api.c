/*
 * E2EE Proxy API implementation.
 *
 * Wire-format constraints that must never change (they are what the Chutes
 * instance expects; see README "E2EE protocol"):
 *   ML-KEM-768        pk 1184 / sk 2400 / ct 1088 / ss 32
 *   KDF               HKDF-SHA256, salt = mlkem_ct[0:16], info = "e2e-*-v1"
 *   AEAD              ChaCha20-Poly1305, 12-byte nonce, 16-byte tag, NO AAD
 *   Compression       gzip (windowBits 15+16), compress-then-encrypt
 *
 * Primitives come from OpenSSL (libcrypto) and zlib, both already present in
 * the OpenResty runtime image. ML-KEM comes from the vendored PQClean sources
 * (native/mlkem/), selectable via mlkem_backend.h.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "e2ee_proxy_api.h"
#include "mlkem_backend.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <zlib.h>

/* from randombytes.c */
int e2ee_secure_random(uint8_t *out, size_t len);

/* ------------------------------------------------------------------------- */
/* init / info                                                               */
/* ------------------------------------------------------------------------- */

E2EE_API int e2ee_init(void) {
    return 0;
}

E2EE_API const char *e2ee_build_info(void) {
    return "e2ee-proxy native"
           " mlkem=" E2EE_MLKEM_BACKEND_NAME
           " crypto=" OPENSSL_VERSION_TEXT
           " zlib=" ZLIB_VERSION
           " built=" __DATE__;
}

/* ------------------------------------------------------------------------- */
/* certificate stubs (ABI compatibility only)                                */
/* ------------------------------------------------------------------------- */

static int no_embedded_material(uint8_t *out, size_t *len) {
    (void)out;
    if (len) *len = 0;
    return -1;
}

E2EE_API int e2ee_get_cert_der(uint8_t *out, size_t *len) {
    return no_embedded_material(out, len);
}
E2EE_API int e2ee_get_intermediate_der(uint8_t *out, size_t *len) {
    return no_embedded_material(out, len);
}
E2EE_API int e2ee_get_root_der(uint8_t *out, size_t *len) {
    return no_embedded_material(out, len);
}
E2EE_API int e2ee_get_privkey_der(uint8_t *out, size_t *len) {
    return no_embedded_material(out, len);
}

/* ------------------------------------------------------------------------- */
/* ML-KEM-768                                                                */
/* ------------------------------------------------------------------------- */

E2EE_API int e2ee_mlkem_keygen(uint8_t pk[E2EE_MLKEM_PK_SIZE],
                               uint8_t sk[E2EE_MLKEM_SK_SIZE]) {
    if (!pk || !sk) return -1;
    return mlkem_keypair(pk, sk) == 0 ? 0 : -1;
}

E2EE_API int e2ee_mlkem_encapsulate(const uint8_t *pk,
                                    uint8_t ct[E2EE_MLKEM_CT_SIZE],
                                    uint8_t ss[E2EE_MLKEM_SS_SIZE]) {
    if (!pk || !ct || !ss) return -1;
    return mlkem_enc(ct, ss, pk) == 0 ? 0 : -1;
}

E2EE_API int e2ee_mlkem_decapsulate(const uint8_t *sk,
                                    const uint8_t ct[E2EE_MLKEM_CT_SIZE],
                                    uint8_t ss[E2EE_MLKEM_SS_SIZE]) {
    if (!sk || !ct || !ss) return -1;
    /*
     * FIPS 203 decapsulation never "fails": an invalid ciphertext yields an
     * implicit-rejection secret. The subsequent AEAD open is what detects it.
     */
    return mlkem_dec(ss, ct, sk) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------------- */
/* HKDF-SHA256                                                               */
/* ------------------------------------------------------------------------- */

E2EE_API int e2ee_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                              const uint8_t *salt, size_t salt_len,
                              const uint8_t *info, size_t info_len,
                              uint8_t *okm, size_t okm_len) {
    if (!ikm || ikm_len == 0 || !okm || okm_len == 0) return -1;
    if (ikm_len > INT_MAX || salt_len > INT_MAX || info_len > INT_MAX) return -1;
    if (okm_len > 255u * 32u) return -1; /* RFC 5869 limit for SHA-256 */

    int rc = -1;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0) goto out;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto out;
    /* Empty salt: RFC 5869 says use HashLen zero bytes; OpenSSL does that when unset. */
    if (salt_len > 0 && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) <= 0) goto out;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) <= 0) goto out;
    if (info_len > 0 && EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) <= 0) goto out;

    size_t outlen = okm_len;
    if (EVP_PKEY_derive(pctx, okm, &outlen) <= 0) goto out;
    if (outlen != okm_len) goto out;
    rc = 0;

out:
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* ChaCha20-Poly1305 (no AAD)                                                */
/* ------------------------------------------------------------------------- */

static int chacha20_poly1305(int encrypt,
                             const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *in, size_t in_len,
                             uint8_t *out, uint8_t tag[16]) {
    if (!key || !nonce || !tag) return -1;
    if (in_len > 0 && (!in || !out)) return -1;

    int rc = -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_CipherInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL, encrypt) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) goto out;
    if (EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce, encrypt) != 1) goto out;
    if (!encrypt && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) != 1) goto out;

    /* No AAD by protocol definition. */

    size_t done = 0;
    while (done < in_len) {
        size_t chunk = in_len - done;
        if (chunk > (size_t)(INT_MAX / 2)) chunk = (size_t)(INT_MAX / 2);
        int outl = 0;
        if (EVP_CipherUpdate(ctx, out + done, &outl, in + done, (int)chunk) != 1) goto out;
        if (outl < 0 || (size_t)outl != chunk) goto out; /* stream cipher: 1:1 */
        done += chunk;
    }

    {
        int outl = 0;
        uint8_t scratch[32];
        /* Final never emits data for ChaCha20; on decrypt it verifies the tag. */
        if (EVP_CipherFinal_ex(ctx, scratch, &outl) != 1) goto out;
        if (outl != 0) goto out;
    }

    if (encrypt && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) goto out;
    rc = 0;

out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

E2EE_API int e2ee_chacha20_seal(const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *plaintext, size_t pt_len,
                                uint8_t *ciphertext, uint8_t tag[16]) {
    return chacha20_poly1305(1, key, nonce, plaintext, pt_len, ciphertext, tag);
}

E2EE_API int e2ee_chacha20_open(const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *ciphertext, size_t ct_len,
                                const uint8_t tag[16], uint8_t *plaintext) {
    int rc = chacha20_poly1305(0, key, nonce, ciphertext, ct_len, plaintext, (uint8_t *)tag);
    if (rc != 0 && plaintext && ct_len > 0) {
        /* Never leak partially-decrypted bytes on authentication failure. */
        memset(plaintext, 0, ct_len);
    }
    return rc;
}

/* ------------------------------------------------------------------------- */
/* gzip                                                                      */
/* ------------------------------------------------------------------------- */

E2EE_API size_t e2ee_gzip_compress(const uint8_t *in, size_t in_len,
                                   uint8_t *out, size_t out_max) {
    if ((in_len > 0 && !in) || !out || out_max == 0) return 0;
    if (in_len > UINT_MAX || out_max > UINT_MAX) return 0;

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     15 + 16 /* gzip wrapper */, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return 0;
    }

    strm.next_in = (Bytef *)in;
    strm.avail_in = (uInt)in_len;
    strm.next_out = (Bytef *)out;
    strm.avail_out = (uInt)out_max;

    int ret = deflate(&strm, Z_FINISH);
    size_t produced = strm.total_out;
    deflateEnd(&strm);

    /* Anything but Z_STREAM_END means the output buffer was too small. */
    if (ret != Z_STREAM_END) return 0;
    return produced;
}

E2EE_API size_t e2ee_gzip_decompress(const uint8_t *in, size_t in_len,
                                     uint8_t *out, size_t out_max) {
    if (!in || in_len == 0 || !out || out_max == 0) return 0;
    if (in_len > UINT_MAX || out_max > UINT_MAX) return 0;

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    if (inflateInit2(&strm, 15 + 32 /* auto-detect gzip/zlib */) != Z_OK) {
        return 0;
    }

    strm.next_in = (Bytef *)in;
    strm.avail_in = (uInt)in_len;
    strm.next_out = (Bytef *)out;
    strm.avail_out = (uInt)out_max;

    int ret = inflate(&strm, Z_FINISH);
    size_t produced = strm.total_out;
    inflateEnd(&strm);

    if (ret != Z_STREAM_END) return 0;
    return produced;
}

/* ------------------------------------------------------------------------- */
/* random                                                                    */
/* ------------------------------------------------------------------------- */

E2EE_API void e2ee_random_bytes(uint8_t *out, size_t len) {
    if (e2ee_secure_random(out, len) != 0) {
        /* Continuing with a predictable nonce would be catastrophic. */
        abort();
    }
}
