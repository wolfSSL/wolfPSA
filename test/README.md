# wolfPSA tests

This directory contains standalone tests and demos for wolfPSA integration.

## Tests

- `psa_api_test`
  - Standalone test for PSA Crypto API calls.
  - Source: `psa_server/psa_api_test.c`

- `wolfcrypt-psa-benchmark`
  - wolfCrypt benchmark that loads `libwolfpsa.so` at runtime and exercises
    PSA-backed code paths via `WOLFSSL_HAVE_PSA`.
  - Source: `wolfcrypt-benchmark/main.c` (build uses local wolfCrypt sources).

- `psa_devid_cryptocb_test`
  - Checks that every algorithm family reaches a registered crypto callback,
    both through wolfCrypt's own device selection and through an explicit
    `wolfPSA_SetDefaultDevID()`, that an explicit `INVALID_DEVID` keeps every
    operation local, and that `WOLFPSA_DEVID_DEFAULT` hands the choice back.
  - Links against its own `WOLF_CRYPTO_CB` build of the library, so it needs no
    prebuilt wolfSSL. That second build is why the test is not part of the
    default `all` target: build it by name with
    `make -C test psa_devid_cryptocb_test`. Its object directory is scoped to
    the flag set (`build-cryptocb`, `build-cryptocb-asan`), so an `ASAN=1`
    build never reuses uninstrumented objects.
  - Source: `psa_server/psa_devid_cryptocb_test.c`

- `psa_secure_set_test`
  - Builds its own library from `test/secure-set/user_settings.h` (NO_ASN, no
    RSA, ChaCha20, DES or PQC, `WOLFPSA_AEAD_BORROW`) and checks raw r||s
    ECDSA including the RFC 6979 vector, refused imports of the compiled-out
    key families, GCM/CCM with overlapping buffers, and streamed HKDF against
    wolfCrypt. Build it by name: `make -C test psa_secure_set_test`.
  - Source: `psa_server/psa_secure_set_test.c`

- `psa_tls_server` + `psa_tls_client`
  - TLS server built with wolfPSA, and a static client built from wolfSSL
    sources (`psa_server/tls_client`).
  - Demonstrates PSA ECC callbacks (sign/verify/ECDH) on the server during the
    TLS handshake.
  - Mutual authentication is enabled. The server pulls its own certificate and
    key from the PSA store and also validates the client certificate against a
    PSA-stored copy (certificate pinning).
  - Shows PSA Store usage using the POSIX PSA store backed by the filesystem
    (see `.store/` under this directory).

## Build

```sh
make -C wolfPSA/test
```

## Run

```sh
# Run the PSA API test
./wolfPSA/test/psa_api_test

# Run the wolfCrypt PSA benchmark
./wolfPSA/test/wolfcrypt-psa-benchmark

# Run the TLS server + client demo (mutual auth, PSA store)
./wolfPSA/test/run_psa_tls_server_client.sh
```
