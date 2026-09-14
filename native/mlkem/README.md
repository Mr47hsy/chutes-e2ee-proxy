# Vendored ML-KEM sources

## `pqclean-ml-kem-768/` + `common/` (default backend)

PQClean `crypto_kem/ml-kem-768/clean` and `common/fips202.{c,h}`,
`common/randombytes.h`, `common/compat.h`, pinned to the commit recorded in `PQCLEAN_COMMIT`.
Licence: Public Domain (CC0), see `pqclean-ml-kem-768/LICENSE`.

This implements **FIPS 203 ML-KEM-768**. The self-test
(`native/build.sh --selftest`) checks it against NIST ACVP known-answer
vectors, including the implicit-rejection case, so a build that passes the
self-test is FIPS 203 by construction.

`randombytes()` is provided by `native/randombytes.c`, not by PQClean.

To refresh:

```bash
SHA=$(curl -s https://api.github.com/repos/PQClean/PQClean/commits/master | jq -r .sha)
for f in LICENSE api.h cbd.c cbd.h indcpa.c indcpa.h kem.c kem.h ntt.c ntt.h params.h \
         poly.c poly.h polyvec.c polyvec.h reduce.c reduce.h symmetric-shake.c symmetric.h verify.c verify.h; do
  curl -sfo native/mlkem/pqclean-ml-kem-768/$f \
    https://raw.githubusercontent.com/PQClean/PQClean/$SHA/crypto_kem/ml-kem-768/clean/$f
done
for f in compat.h fips202.c fips202.h randombytes.h; do
  curl -sfo native/mlkem/common/$f https://raw.githubusercontent.com/PQClean/PQClean/$SHA/common/$f
done
echo $SHA > native/mlkem/PQCLEAN_COMMIT
```

## `kyber-r3/` (fallback backend, not vendored)

Only needed if an end-to-end request against a real Chutes instance fails to
decrypt while the self-test passes: that would mean the instances still speak
**Kyber round-3**, which has identical sizes but a different shared-secret
derivation.

The upstream proxy's obfuscated `.so` linked `pqcrystals_kyber768_ref_*`
compiled with `-DKYBER_K=3`, and the current pq-crystals `main` branch is
FIPS 203 behind those same symbol names, so this fallback is not expected to
be necessary. It is kept as a documented, one-variable switch rather than a
rewrite.

To enable it:

1. Obtain the pq-crystals **round-3** reference sources (the `round3` tag of
   https://github.com/pq-crystals/kyber, directory `ref/`).
2. Copy `kem.c indcpa.c poly.c polyvec.c ntt.c cbd.c reduce.c verify.c
   fips202.c symmetric-shake.c` and their headers into `native/mlkem/kyber-r3/`.
   Do **not** copy `randombytes.c`; provide the same `randombytes(uint8_t*, size_t)`
   prototype by adding a tiny `randombytes.h` there that declares
   `void randombytes(uint8_t *out, size_t outlen);` and a `randombytes.c` that
   forwards to `e2ee_secure_random` (see `native/randombytes.c`).
3. Build with `MLKEM_BACKEND=kyber-r3` (`docker build --build-arg MLKEM_BACKEND=kyber-r3 .`).

The self-test will report that the FIPS 203 KATs are skipped for this backend.
