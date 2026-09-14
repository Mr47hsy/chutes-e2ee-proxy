/*
 * randombytes.c - single CSPRNG source for the whole library.
 *
 * Serves both the public e2ee_random_bytes() and PQClean's randombytes()
 * (used inside ML-KEM keygen/encaps).
 *
 * Order of preference:
 *   Linux   getrandom(2) (blocks only until the pool is seeded), then /dev/urandom
 *   macOS   arc4random_buf(3)
 *   other   /dev/urandom
 * rand(3) is never used.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "randombytes.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <stdlib.h>
#endif

#if !defined(__APPLE__)
static int fill_from_urandom(uint8_t *out, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = 0;
    while (got < len) {
        size_t r = fread(out + got, 1, len - got, f);
        if (r == 0) {
            fclose(f);
            return -1;
        }
        got += r;
    }
    fclose(f);
    return 0;
}
#endif

/* Returns 0 on success, -1 if no entropy source could be used. */
int e2ee_secure_random(uint8_t *out, size_t len) {
    if (len == 0) return 0;
    if (!out) return -1;

#if defined(__linux__)
    size_t got = 0;
    while (got < len) {
        ssize_t r = getrandom(out + got, len - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            /* ENOSYS on very old kernels / seccomp: fall back below */
            break;
        }
        got += (size_t)r;
    }
    if (got == len) return 0;
    return fill_from_urandom(out, len);
#elif defined(__APPLE__)
    arc4random_buf(out, len);
    return 0;
#else
    return fill_from_urandom(out, len);
#endif
}

/* PQClean hook (prototype in mlkem/common/randombytes.h). */
int PQCLEAN_randombytes(uint8_t *output, size_t n) {
    if (e2ee_secure_random(output, n) != 0) {
        /* ML-KEM must never proceed with unfilled coins. */
        abort();
    }
    return 0;
}
