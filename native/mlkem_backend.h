/*
 * mlkem_backend.h - selects the ML-KEM-768 implementation linked into
 * libe2ee_proxy.so.
 *
 * WHY A SWITCH EXISTS
 * -------------------
 * Kyber round-3 and FIPS 203 ML-KEM share every byte size (pk 1184, sk 2400,
 * ct 1088, ss 32) but derive the shared secret differently, so they do NOT
 * interoperate. Picking the wrong one passes every local size check and every
 * local round-trip test, and only fails when the real Chutes instance cannot
 * open the request (surfacing as a 400/500, not a crypto error).
 *
 * Evidence that Chutes speaks FIPS 203 (the default here):
 *   - The upstream (obfuscated) .so linked pqcrystals_kyber768_ref_* symbols
 *     from the pq-crystals/kyber tree with -DKYBER_K=3. The current pq-crystals
 *     `main` branch implements FIPS 203 (no H(m) pre-hash, no final KDF over
 *     the ciphertext, implicit rejection via J(z||c)) while keeping the old
 *     "kyber" symbol names.
 *   - Chutes' own announcement describes "ML-KEM-768, the NIST standard".
 *
 * The only proof that matters is an end-to-end request against a real
 * instance (README, "Verifying the ML-KEM variant"). If that fails while
 * everything else checks out, rebuild with MLKEM_BACKEND=kyber-r3 (see
 * native/build.sh and native/mlkem/README.md).
 */
#ifndef E2EE_MLKEM_BACKEND_H
#define E2EE_MLKEM_BACKEND_H

#include <stdint.h>

#if !defined(E2EE_MLKEM_BACKEND_PQCLEAN) && !defined(E2EE_MLKEM_BACKEND_KYBER_R3)
#define E2EE_MLKEM_BACKEND_PQCLEAN 1
#endif

#if defined(E2EE_MLKEM_BACKEND_PQCLEAN)

#include "kem.h" /* PQClean crypto_kem/ml-kem-768/clean */

#define E2EE_MLKEM_BACKEND_NAME "pqclean-ml-kem-768 (FIPS 203)"
#define mlkem_keypair        PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair
#define mlkem_enc            PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc
#define mlkem_dec            PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec
/* Deterministic variants, used only by the self-test for NIST KATs. */
#define mlkem_keypair_derand PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand
#define mlkem_enc_derand     PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand
#define E2EE_MLKEM_HAS_DERAND 1

#elif defined(E2EE_MLKEM_BACKEND_KYBER_R3)

/*
 * Fallback: pq-crystals kyber round-3 reference implementation, compiled with
 * -DKYBER_K=3. Drop the round-3 sources into native/mlkem/kyber-r3/ (see
 * native/mlkem/README.md) and build with MLKEM_BACKEND=kyber-r3.
 */
int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#define E2EE_MLKEM_BACKEND_NAME "pq-crystals kyber768 round-3 (NOT FIPS 203)"
#define mlkem_keypair pqcrystals_kyber768_ref_keypair
#define mlkem_enc     pqcrystals_kyber768_ref_enc
#define mlkem_dec     pqcrystals_kyber768_ref_dec
#define E2EE_MLKEM_HAS_DERAND 0

#else
#error "no ML-KEM backend selected"
#endif

#endif /* E2EE_MLKEM_BACKEND_H */
