# wolfPSA

wolfPSA provides the Mbed TLS 4.x API on top of wolfCrypt, wolfSSL's crypto
library. Built with `MBEDTLS_COMPAT=1` against wolfSSL master, it lets
applications written for Mbed TLS 4.x build without source changes and link
`libwolfpsa.a` in place of Mbed TLS's libraries. Parts of the API are not
available yet, such as session tickets, ALPN and DTLS, and some behave
differently: see [coming soon][soon] and the [known differences][differences].

[soon]: docs/mbedtls-compatibility.md#coming-soon
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
- Parts of TF-PSA-Crypto, in every build: `mbedtls/pk.h` key parsing,
  `mbedtls/base64.h`, `mbedtls/threading.h` and `mbedtls/platform.h`. See
  [currently supported](docs/mbedtls-compatibility.md#currently-supported).

## Mbed TLS compatibility

`MBEDTLS_COMPAT=1` adds the Mbed TLS 4.x TLS, X.509, PEM and network API on
top of wolfSSL. wolfPSA already provides the TF-PSA-Crypto side (`psa_*`,
`mbedtls_pk_*`, `mbedtls_base64_*`, `mbedtls_psa_crypto_free`,
`mbedtls/platform.h`).

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

wolfPSA requires a C99 compiler, as TF-PSA-Crypto and Mbed TLS do.

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

`PSA_WANT_WITHOUT` removes an algorithm from the PSA surface while wolfCrypt
keeps its primitive, for example when the application seals with one-shot
AES-GCM but should not offer GCM through PSA:
`make PSA_WANT_WITHOUT=PSA_WANT_ALG_GCM`. It takes `PSA_WANT_ALG_GCM`,
`PSA_WANT_ALG_CCM`, `PSA_WANT_ALG_CHACHA20_POLY1305`,
`PSA_WANT_ALG_SP800_108_COUNTER_HMAC` and `PSA_WANT_ALG_SP800_108_COUNTER_CMAC`,
and that algorithm then returns `PSA_ERROR_NOT_SUPPORTED`. Every other algorithm follows the wolfCrypt
build, so turn it off there.

`WOLFPSA_ECC_SP_DIRECT` runs P-256 ECDSA (randomized only), ECDH, key
generation and key import straight on wolfCrypt's SP code, so `ecc.c` and the
multi-precision math leave a P-256-only build. It keeps `ecc.c`'s checks: the
private key is in [1, n-1], public points are on the curve with coordinates
below p, and r and s are in [1, n-1]. It needs `WOLFSSL_HAVE_SP_ECC` and
`ECC_USER_CURVES` with every other curve off; `test/ecc-direct` is an example
configuration, and `wolfpsa/psa_p256.h` declares the same primitives for
code built into the same image.

## Repository layout

- `src/` : wolfPSA implementation sources.
- `wolfpsa/` : public headers.
- `user_settings.h` : configuration header.
- `Makefile` : build for `libwolfpsa.a`.

`WOLFPSA_AEAD_BORROW` lets one-shot GCM and CCM read the caller's AAD and
message in place instead of copying them, which saves a message-sized buffer.
Define it only when nothing else can change those buffers during the call,
for example a Secure service whose inputs sit in its own memory. Outputs that
partly overlap the input or overlap the AAD still take the copying path.

`WOLFPSA_AEAD_STREAM_AAD` feeds multipart GCM and ChaCha20-Poly1305 AAD into
the cipher as `psa_aead_update_ad()` receives it, so the operation holds no
copy of the AAD however long it is. `psa_aead_update()` then needs an output
buffer, as the PSA Crypto API requires: the buffered mode that takes a NULL
output and emits everything from `psa_aead_finish()` is refused.

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
