# wolfPSA

wolfPSA provides the Mbed TLS 4.x API on top of wolfCrypt, wolfSSL's crypto
library. Built with `MBEDTLS_COMPAT=1` against wolfSSL master, it lets
applications written for Mbed TLS 4.x build without source changes and link
`libwolfpsa.a` in place of Mbed TLS's libraries. Parts of the API are not
available yet, such as verify callbacks and `MBEDTLS_SSL_VERIFY_OPTIONAL`:
see the [known differences][differences].

[differences]: docs/mbedtls-compatibility.md#known-differences-from-mbed-tls

wolfPSA also implements the PSA Crypto API and parts of TF-PSA-Crypto, the
crypto library of Mbed TLS 4.x. Without the Mbed TLS layer, it serves as a
PSA Crypto engine for PSA clients such as wolfSSL compiled with
`WOLFSSL_HAVE_PSA` or the Arm PSA Architecture Test Suite.

## What it provides

- The Mbed TLS 4.x TLS, X.509, PEM and network API, when built with
  `MBEDTLS_COMPAT=1`. See [Mbed TLS compatibility](#mbed-tls-compatibility).
- PSA Crypto API implemented in C.
- wolfCrypt as the backend crypto provider.
- The default make target creates a static library (`libwolfpsa.a`) built directly
  from wolfPSA sources plus the required wolfCrypt objects.
- TF-PSA-Crypto's `mbedtls/pk.h` for private and public keys:
  `mbedtls_pk_init`, `free`, `parse_key`, `parse_keyfile`,
  `parse_public_key`, `parse_public_keyfile`, `get_bitlen` and `can_do_psa`.
  The context has a private key's DER, or a public key's
  SubjectPublicKeyInfo DER, with its type and size. Private keys are RSA
  and EC, PEM or DER, traditional or PKCS #8. Public keys are RSA, EC, X25519
  and X448, PEM or DER, SubjectPublicKeyInfo or, for RSA, PKCS #1. EC keys
  are on the curves the PSA engine has. Encrypted keys and EC keys with a
  compressed public key are not supported.

## Mbed TLS compatibility

`MBEDTLS_COMPAT=1` adds the Mbed TLS 4.x TLS, X.509, PEM and network API on
top of wolfSSL. wolfPSA already provides the TF-PSA-Crypto side (`psa_*`,
`mbedtls_pk_*`, `mbedtls_psa_crypto_free`, `mbedtls/platform.h`).

Build wolfPSA with `MBEDTLS_COMPAT=1` as in [Build](#build). Applications
then use `-I<wolfPSA>/wolfpsa`, `-I<wolfPSA>/wolfpsa/mbedtls_compat` and
`-I<wolfPSA>/build/include`, and link `libwolfpsa.a`, in place of Mbed TLS's
libraries. The headers include no wolfSSL header.

To run the compatibility tests:

```
make MBEDTLS_COMPAT=1 mbedtls-compat-test
```

See [docs/mbedtls-compatibility.md](docs/mbedtls-compatibility.md) for the
supported functions, what is coming soon, the known differences from Mbed TLS,
and the build and test details.

## Build

wolfPSA compiles wolfCrypt, and with `MBEDTLS_COMPAT=1` wolfSSL's TLS, from a
wolfSSL source tree. By default this is `../wolfssl`, a clone of wolfSSL
master next to this repository:

```
git clone https://github.com/wolfSSL/wolfssl ../wolfssl
```

`MBEDTLS_COMPAT=1` needs wolfSSL master. Without it, wolfPSA also builds
against the matching wolfSSL release: wolfPSA v5.9.4 is tested against
wolfSSL `v5.9.4-stable`. To use a wolfSSL tree elsewhere, set
`WOLFSSL_PATH`, for example `make WOLFSSL_PATH=~/src/wolfssl`.

Build with the Mbed TLS API:

```
make MBEDTLS_COMPAT=1
```

Or with the PSA Crypto API only:

```
make
```

Options, which can be combined (`make help` lists them all):

- `ASAN=1`: AddressSanitizer build.
- `MBEDTLS_THREADING_C=1`: thread-safe build, as Mbed TLS with
  `MBEDTLS_THREADING_C`: wolfCrypt without `SINGLE_THREADED`, a mutex around
  the key store (`WOLFPSA_THREAD_SAFE`, see `src/psa_lock.h`) and the
  TF-PSA-Crypto threading API in `mbedtls/threading.h`, on pthreads.
  Applications define `MBEDTLS_THREADING_C` too, as in their Mbed TLS
  configuration, and link with `-pthread`.

The build generates the `PSA_WANT_*` macros from the wolfCrypt configuration
into `$(BUILD_DIR)/include/crypto_config_generated.h` (`build/include` by
default), using python3. Set `PYTHON` to use another interpreter. Code that
includes `<psa/crypto.h>` needs that directory on its include path next to
`wolfpsa/`, and builds only after `make` has generated the header.

## Repository layout

- `src/` : wolfPSA implementation sources.
- `wolfpsa/` : public headers.
- `user_settings.h` : configuration header.
- `Makefile` : build for `libwolfpsa.a`.

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
