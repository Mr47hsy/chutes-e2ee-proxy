/*
 * E2EE Proxy API - shared library for the OpenResty/Lua proxy.
 *
 * The signatures below are consumed verbatim by lua/e2ee_crypto.lua through
 * LuaJIT FFI (ffi.cdef). Do not change them without changing the cdef.
 *
 * Return-value conventions:
 *   int functions       0 = success, non-zero = failure
 *   size_t gzip funcs   number of bytes written, 0 = failure
 */

#ifndef E2EE_PROXY_API_H
#define E2EE_PROXY_API_H

#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32)
#define E2EE_API __declspec(dllexport)
#else
#define E2EE_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Initialization. Always succeeds in this fork (no anti-debug, no caller checks). */
E2EE_API int e2ee_init(void);

/* Human-readable build description: ML-KEM backend, crypto provider, build date. */
E2EE_API const char *e2ee_build_info(void);

/*
 * TLS certificate & key retrieval (DER).
 *
 * Kept for ABI compatibility with the upstream .so. This fork does not embed
 * any certificate material; all four always return -1 and set *len = 0.
 * TLS is configured from files by entrypoint.sh instead.
 */
E2EE_API int e2ee_get_cert_der(uint8_t *out, size_t *len);
E2EE_API int e2ee_get_intermediate_der(uint8_t *out, size_t *len);
E2EE_API int e2ee_get_root_der(uint8_t *out, size_t *len);
E2EE_API int e2ee_get_privkey_der(uint8_t *out, size_t *len);

/* ML-KEM-768 Post-Quantum Key Encapsulation */

#define E2EE_MLKEM_PK_SIZE   1184
#define E2EE_MLKEM_SK_SIZE   2400
#define E2EE_MLKEM_CT_SIZE   1088
#define E2EE_MLKEM_SS_SIZE   32

E2EE_API int e2ee_mlkem_keygen(uint8_t pk[E2EE_MLKEM_PK_SIZE],
                               uint8_t sk[E2EE_MLKEM_SK_SIZE]);

E2EE_API int e2ee_mlkem_encapsulate(const uint8_t *pk,
                                    uint8_t ct[E2EE_MLKEM_CT_SIZE],
                                    uint8_t ss[E2EE_MLKEM_SS_SIZE]);

E2EE_API int e2ee_mlkem_decapsulate(const uint8_t *sk,
                                    const uint8_t ct[E2EE_MLKEM_CT_SIZE],
                                    uint8_t ss[E2EE_MLKEM_SS_SIZE]);

/* HKDF-SHA256 Key Derivation (RFC 5869) */
E2EE_API int e2ee_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                              const uint8_t *salt, size_t salt_len,
                              const uint8_t *info, size_t info_len,
                              uint8_t *okm, size_t okm_len);

/*
 * ChaCha20-Poly1305 AEAD (RFC 8439), 96-bit nonce, 128-bit tag, NO AAD.
 * ciphertext/plaintext buffers must hold pt_len / ct_len bytes; they may alias.
 */
E2EE_API int e2ee_chacha20_seal(const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *plaintext, size_t pt_len,
                                uint8_t *ciphertext, uint8_t tag[16]);

E2EE_API int e2ee_chacha20_open(const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *ciphertext, size_t ct_len,
                                const uint8_t tag[16], uint8_t *plaintext);

/* Gzip (RFC 1952 framing, not raw deflate). Returns bytes written, 0 on failure. */
E2EE_API size_t e2ee_gzip_compress(const uint8_t *in, size_t in_len,
                                   uint8_t *out, size_t out_max);

E2EE_API size_t e2ee_gzip_decompress(const uint8_t *in, size_t in_len,
                                     uint8_t *out, size_t out_max);

/* Random bytes (CSPRNG). Aborts the process if no entropy source works. */
E2EE_API void e2ee_random_bytes(uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* E2EE_PROXY_API_H */
