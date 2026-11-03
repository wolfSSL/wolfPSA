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
  DER and type. RSA and EC keys, PEM or DER, traditional or PKCS #8.
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

## Mbed TLS compatibility

`MBEDTLS_COMPAT=1` adds the Mbed TLS 4.x TLS, X.509 and network API on top of
wolfSSL, so that applications written for Mbed TLS 4.x build against wolfPSA
without source changes. wolfPSA already provides the TF-PSA-Crypto side
(`psa_*`, `mbedtls_psa_crypto_free`, `mbedtls/platform.h`).

```
make MBEDTLS_COMPAT=1
```

- wolfSSL's TLS sources are compiled from `WOLFSSL_PATH` into
  `libwolfpsa.a`, like wolfCrypt, with the TLS settings in
  `user_settings.h`. Changing the option rebuilds everything.
- Applications use `-I<wolfPSA>/wolfpsa` and `-I<wolfPSA>/build/include`, and
  link `libwolfpsa.a`, in place of Mbed TLS's libraries. The headers include
  no wolfSSL header.
- The functions have the Mbed TLS names, so code that finds them by symbol
  name (`dlsym`, language bindings) works too.
- With `MBEDTLS_THREADING_C=1`, TLS is thread safe too.
- TLS uses wolfPSA's constant-time AES. `AES_FAST=1` applies to TLS too.
- As in Mbed TLS, certificates may have NULL parameters after an ECDSA
  signature OID (`WOLFSSL_ECC_SIGALG_PARAMS_NULL_ALLOWED`).

Mapped so far:

- net: init, connect, bind, accept, close, free, recv, send, usleep
- x509_crt: init, free, parse, parse_der, parse_file
- ssl_config: init, free, defaults; ssl_conf: authmode, ca_chain, own_cert,
  dbg
- ssl: init, free, setup, session_reset, set_bio, set_hostname, handshake,
  get_verify_result, get_ciphersuite, read, write, close_notify
- pk, with or without the option: init, free, parse_key, parse_keyfile
- threading, with `MBEDTLS_THREADING_C=1`, with or without the option: mutex
  init, free, lock, unlock; condition_variable init, free, signal, broadcast,
  wait

Known differences from Mbed TLS:

- A wolfSSL error with no Mbed TLS match returns a general code for the
  call, such as `MBEDTLS_ERR_SSL_INTERNAL_ERROR`. wolfSSL's own codes are not
  returned: some Mbed TLS 4.x codes are PSA values (-128 to -160), which
  overlap wolfCrypt codes.
- `conf_*` calls after `mbedtls_ssl_setup` take effect at the next
  `mbedtls_ssl_session_reset`.
- A second `mbedtls_ssl_conf_own_cert` replaces the first. Mbed TLS keeps
  both and picks one for each handshake.
- `mbedtls_ssl_get_ciphersuite` returns IANA names, such as
  `TLS_AES_128_GCM_SHA256`, where Mbed TLS has `TLS1-3-AES-128-GCM-SHA256`.
- `mbedtls_net_accept` is TCP only.
- `mbedtls_pk_context` has the key's DER and nothing else. Encrypted keys
  and EC keys with a compressed public key are not supported.
- `mbedtls_x509_crt` has one node per certificate, with no parsed fields
  apart from `raw`. Parse errors are `MBEDTLS_ERR_X509_INVALID_FORMAT` or
  `MBEDTLS_ERR_X509_ALLOC_FAILED`.
- wolfSSL parses some certificates differently. For example, it rejects
  serial number 0 and a pathlen above `WOLFSSL_MAX_PATH_LEN`, and accepts
  spaces in PEM.
- `mbedtls_ssl_conf_ca_chain` leaves out a CA that wolfSSL does not load,
  such as an expired one. A peer certificate from that CA then fails as
  `NOT_TRUSTED`, where Mbed TLS reports `EXPIRED`.
- An IP address host name is matched against the certificate's IP address
  SANs only. Mbed TLS also matches a DNS SAN with the same text, or the CN
  of a certificate without SANs.
- `mbedtls_ssl_set_hostname(ssl, NULL)` after `mbedtls_ssl_setup` starts a
  new connection, so call it before the handshake.
- With `VERIFY_OPTIONAL`, a resumed session reports
  `MBEDTLS_X509_BADCERT_MISSING`, where Mbed TLS keeps the result of the
  first handshake.
- With `VERIFY_REQUIRED`, wolfSSL stops at the first failed check, so
  `mbedtls_ssl_get_verify_result` can report fewer flags than Mbed TLS.
- `mbedtls_ssl_conf_dbg` is accepted and ignored.
- No global mutexes such as `mbedtls_threading_gmtime_mutex`.

Tests build the Mbed TLS migration guide client
(`test/mbedtls_compat/client-tls-mbedtls.c`) and Mbed TLS's sample
programs, unchanged, against `libwolfpsa.a`, and run them against the
wolfSSL example server. Mbed TLS's server programs run against the wolfSSL
example client and `ssl_client1`. `test/mbedtls_compat/x509_crt_test.c` and
`pk_test.c` parse Mbed TLS's test certificates and keys. With
`MBEDTLS_THREADING_C=1`, `ssl_pthread_server` serves clients at the same
time. To run them:

```
make MBEDTLS_COMPAT=1 mbedtls-compat-test
```

- `MBEDTLS_PATH` (default `../mbedtls`) is an Mbed TLS 4.x checkout with
  its submodules. Nothing from Mbed TLS is copied or linked, apart from its
  test certificate data.
- The example server and client come from a wolfSSL configured out of tree
  from `WOLFSSL_PATH`, which must not be configured in place. The tests use
  the certificates in its `certs/`.
- Also needs python3 with jinja2. Without faketime, the case that needs it
  is skipped.
- `WRAP` prefixes each test program, for example `WRAP=valgrind`. Server
  programs are stopped by the script, so their exit codes are not checked.

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
