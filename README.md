# wolfPSA

wolfPSA is a PSA Crypto **engine** that implements the PSA Crypto API on
 top of wolfCrypt. It is meant to be used by PSA clients (e.g. wolfSSL compiled with `WOLFSSL_HAVE_PSA`, 
 or the Arm PSA Architecture Test Suite).

## What it provides

- PSA Crypto API entry points implemented in C.
- wolfCrypt as the backend crypto provider.
- The default make target creates a static library (`libwolfpsa.a`) built directly
  from wolfPSA sources plus the required wolfCrypt objects.
- TF-PSA-Crypto's `mbedtls/pk.h` for private keys: `mbedtls_pk_init`, `free`,
  `parse_key`, `parse_keyfile` and `can_do_psa`. The context has the key's
  DER and nothing else. RSA and EC keys, PEM or DER, traditional or PKCS #8.
  Encrypted keys and EC keys with a compressed public key are not supported.

## Repository layout

- `src/` : wolfPSA implementation sources.
- `wolfpsa/` : public headers.
- `user_settings.h` : configuration header.
- `Makefile` : build for `libwolfpsa.a`.

## Build

### wolfSSL version

wolfPSA follows wolfSSL version numbering: wolfPSA v5.9.4 is tested against
wolfSSL `v5.9.4-stable`. To build against the matching release:

```
git clone --branch v5.9.4-stable https://github.com/wolfSSL/wolfssl
```

CI also tests against wolfSSL master.

### Building

The build system assumes that wolfSSL is available in a sibling directory under
the same path as this repository, e.g:

```
.
├── wolfPSA/
├── wolfssl/
```

If this is not the case, provide the path to wolfSSL sources via:

```
export WOLFSSL_PATH=../wolfssl
```

Default build:

```
make
```

AddressSanitizer build:

```
make ASAN=1
```

Thread-safe build, as Mbed TLS with `MBEDTLS_THREADING_C`: wolfCrypt without
`SINGLE_THREADED`, a mutex around the key store (`WOLFPSA_THREAD_SAFE`, see
`src/psa_lock.h`) and the TF-PSA-Crypto threading API in
`mbedtls/threading.h`, on pthreads:

```
make MBEDTLS_THREADING_C=1
```

Applications define `MBEDTLS_THREADING_C` too, as in their Mbed TLS
configuration, and link with `-pthread`.

You can override the wolfSSL source location:

```
make wolfPSA WOLFSSL_PATH=~/src/wolfssl
```

The build generates the `PSA_WANT_*` macros from the wolfCrypt configuration
into `$(BUILD_DIR)/include/crypto_config_generated.h` (`build/include` by
default), using python3. Set `PYTHON` to use another interpreter. Code that
includes `<psa/crypto.h>` needs that directory on its include path next to
`wolfpsa/`, and builds only after `make` has generated the header.

## Testing (PSA Architecture Test Suite)

See `test-psa-api/README.md` for instructions on how to run the tests.

### Current PSA crypto test results (wolfSSL v5.9.4-stable):

```
************ Crypto Suite Report ************
TOTAL TESTS     : 78
TOTAL PASSED    : 65
TOTAL SIM ERROR : 0
TOTAL FAILED    : 0
TOTAL SKIPPED   : 13
******************************************
```


## License

See `COPYING`.

## ChangeLog

See `CHANGELOG.md`.
