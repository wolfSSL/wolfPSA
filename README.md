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
(`psa_*`, `mbedtls_pk_*`, `mbedtls_psa_crypto_free`, `mbedtls/platform.h`).

```
make MBEDTLS_COMPAT=1
```

- wolfSSL's TLS sources are compiled from `WOLFSSL_PATH` into
  `libwolfpsa.a`, like wolfCrypt, with the TLS settings in `user_settings.h`.
  Changing the option rebuilds everything.
- Needs a current wolfSSL built from its master branch. wolfSSL releases,
  such as v5.9.4-stable, are not supported.
- Applications use `-I<wolfPSA>/wolfpsa`,
  `-I<wolfPSA>/wolfpsa/mbedtls_compat` and `-I<wolfPSA>/build/include`, and
  link `libwolfpsa.a`, in place of Mbed TLS's libraries. The headers include
  no wolfSSL header.
- The feature macros, such as `MBEDTLS_SSL_TLS_C`, `MBEDTLS_NET_C` and
  `MBEDTLS_PEM_PARSE_C`, are in the generated config in `build/include`, so
  a build without the option does not define them.
- The functions have the Mbed TLS names, so code that finds them by symbol
  name (`dlsym`, language bindings) works too.
- With `MBEDTLS_THREADING_C=1`, TLS is thread safe too.
- TLS uses wolfPSA's constant-time AES. `AES_FAST=1` applies to TLS too.
- As in Mbed TLS, certificates may have NULL parameters after an ECDSA
  signature OID. This needs `WOLFSSL_ECC_SIGALG_PARAMS_NULL_ALLOWED`, which
  wolfPSA's `user_settings.h` defines. A build with its own
  `USER_SETTINGS_PATH` defines it too, or rejects such certificates, for
  example Mbed TLS's `test-ca2.crt`.
- The X.509 API needs wolfCrypt's certificate parsing: without it (`NO_ASN`
  or `NO_CERTS`), `MBEDTLS_X509_CRT_PARSE_C` is not defined.
- TLS needs the X.509 API and wolfSSL's TLS with `HAVE_SNI`: without them,
  for example with `WOLFCRYPT_ONLY`, `MBEDTLS_SSL_TLS_C` is not defined.
  `MBEDTLS_NET_C` needs TLS and wolfSSL's socket I/O (no `WOLFSSL_USER_IO`).
  `MBEDTLS_PEM_PARSE_C` needs wolfCrypt's Base64 decoding (no `NO_CODING`).

Mapped so far:

- net: init, connect, bind, accept, close, free, recv, send, usleep
- pem: init, read_buffer, get_buffer, free
- x509_crt: init, free, parse, parse_der, parse_file, parse_path; the
  default, next and suiteb profiles, as names only
- ssl_config: init, free, defaults; ssl_conf: authmode, ca_chain, own_cert,
  min_tls_version, max_tls_version, ciphersuites, cert_profile, dbg,
  endpoint, transport, get_endpoint, set_user_data_p, set_user_data_n,
  get_user_data_p, get_user_data_n
- ssl: init, free, setup, context_get_config, session_reset, set_bio,
  set_hostname, set_session, get_session, handshake, is_handshake_over,
  get_verify_result, get_ciphersuite, get_ciphersuite_id_from_ssl,
  get_version, get_version_number, get_bytes_avail, read, write,
  close_notify, set_user_data_p, set_user_data_n, get_user_data_p,
  get_user_data_n; list_ciphersuites, get_ciphersuite_name,
  get_ciphersuite_id
- ssl_session: init, free; save and load return
  `MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE`

Known differences from Mbed TLS:

- `MBEDTLS_SSL_VERIFY_OPTIONAL`, `mbedtls_ssl_conf_verify` and
  `mbedtls_ssl_set_verify` are not available yet, so an application that
  uses them does not build.
- With `MBEDTLS_SSL_VERIFY_REQUIRED`, the handshake stops at the first check
  of the peer's chain that fails, and `mbedtls_ssl_get_verify_result` has
  only its flag. Mbed TLS checks the whole chain first and reports the flag
  of each failure.
- A wolfSSL error with no Mbed TLS match returns a general code for the
  call, such as `MBEDTLS_ERR_SSL_INTERNAL_ERROR`. wolfSSL's own codes are not
  returned: some Mbed TLS 4.x codes are PSA values (-128 to -160), which
  overlap wolfCrypt codes.
- A config needs `mbedtls_ssl_config_defaults`. `mbedtls_ssl_conf_endpoint`
  and `mbedtls_ssl_conf_transport` cannot change the endpoint and transport
  it set: `mbedtls_ssl_setup` and the handshake then return
  `MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE`. wolfSSL makes its config for one
  endpoint and transport.
- `mbedtls_ssl_conf_ca_chain` refuses a CRL: `mbedtls_ssl_setup` and the
  handshake then return `MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE`.
- A server's config needs its `mbedtls_ssl_conf_own_cert` before
  `mbedtls_ssl_setup`, which fails without it: wolfSSL makes a server
  connection only with a certificate and key.
- A second `mbedtls_ssl_conf_own_cert` replaces the first. Mbed TLS keeps
  both and picks one for each handshake.
- `mbedtls_ssl_get_ciphersuite` returns IANA names, such as
  `TLS_AES_128_GCM_SHA256`, where Mbed TLS has `TLS1-3-AES-128-GCM-SHA256`.
- `mbedtls_net_accept` is TCP only.
- RSA keys are limited to 3072 bits, so a certificate chain with an RSA-4096
  CA does not verify.
- `mbedtls_ssl_conf_ca_chain` leaves out a CA that wolfSSL does not load,
  such as an expired one. A peer certificate from that CA then fails as
  `NOT_TRUSTED`, where Mbed TLS reports `EXPIRED`.
- A certificate's issuer name must match its CA's subject name exactly, as
  encoded. Mbed TLS also takes names that differ only in letter case or in
  string type (PrintableString or UTF8String). Such a certificate fails as
  `NOT_TRUSTED`. For example, Mbed TLS's test certificate `cli2.crt` has
  issuer `PolarSSL Test EC CA`, and its CA `test-ca2.crt` has subject
  `Polarssl Test EC CA`.
- An IP address host name is matched against the certificate's IP address
  SANs only. Mbed TLS also matches a DNS SAN with the same text, or the CN
  of a certificate without SANs.
- A host name without a dot, such as `router`, fails with
  `MBEDTLS_ERR_SSL_BAD_INPUT_DATA` from `mbedtls_ssl_set_hostname`, or from
  `mbedtls_ssl_setup` when set before it. wolfSSL takes only a fully
  qualified name, an IP address or `localhost`.
- `mbedtls_ssl_set_hostname` during a handshake applies from the next
  `mbedtls_ssl_session_reset`. Mbed TLS uses the new name for the rest of
  that handshake.
- A server resumes sessions from wolfSSL's session cache, where Mbed TLS
  needs `mbedtls_ssl_conf_session_cache`. A server that verifies client
  certificates reports `MBEDTLS_X509_BADCERT_MISSING` for a resumed session.
- wolfSSL keeps the intermediate CAs of a chain that verifies, for the
  config's later handshakes. A peer that then leaves them out still
  verifies, where Mbed TLS reports `NOT_TRUSTED`.
- `mbedtls_ssl_conf_dbg` and `mbedtls_ssl_conf_cert_profile` are accepted
  and ignored.
- `mbedtls_pem_read_buffer` returns `MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE`
  for encrypted PEM. No `mbedtls_pem_write_buffer`.
- `mbedtls_x509_crt` has one node per certificate, with no parsed fields
  apart from `raw`. Parse errors are `MBEDTLS_ERR_X509_INVALID_FORMAT` or
  `MBEDTLS_ERR_X509_ALLOC_FAILED`.
- `mbedtls_x509_crt_parse_path` needs `<dirent.h>`. On Windows, or with
  `NO_WOLFSSL_DIR`, it returns `MBEDTLS_ERR_X509_FILE_IO_ERROR`.
- The profiles are not applied: wolfSSL's own limits hold.
  `mbedtls_x509_crt_profile` is opaque, so applications cannot define their
  own.
- wolfSSL parses some certificates differently. For example, it rejects
  serial number 0 and a pathlen above `WOLFSSL_MAX_PATH_LEN`, and accepts
  spaces in PEM.
- No global mutexes such as `mbedtls_threading_gmtime_mutex`.

### Mbed TLS compatibility tests

```
make MBEDTLS_COMPAT=1 mbedtls-compat-test
```

runs these against `libwolfpsa.a`. Each is also a target of its own.

- `mbedtls-compat-unit`: `test/mbedtls_compat/x509_crt_test.c`,
  `pk_test.c` and `pem_test.c` parse Mbed TLS's test certificates and keys.
  `ssl_test.c` checks return codes and verify results, client and server in
  one process.
- `mbedtls-compat-programs`: the Mbed TLS migration guide client
  (`test/mbedtls_compat/client-tls-mbedtls.c`) and Mbed TLS's sample
  programs, built unchanged, run against the wolfSSL example server. Mbed
  TLS's server programs run against the wolfSSL example client. With
  `MBEDTLS_THREADING_C=1`, `ssl_pthread_server` serves clients at the same
  time.

Notes:

- `MBEDTLS_PATH` (default `../mbedtls`) is an Mbed TLS 4.x checkout with
  its `framework` and `tf-psa-crypto` submodules, for its test data and
  sample programs.
- The example server and client come from a wolfSSL configured out of tree
  from `WOLFSSL_PATH`, which must not be configured in place. The tests use
  the certificates in its `certs/`. This needs autoconf, automake and
  libtool.
- Also needs python3 with jinja2. Without faketime, the case that needs it
  is skipped.
- `WRAP` prefixes each test program, for example `WRAP=valgrind`. Server
  programs are stopped by the script, so their exit codes are not checked.
- `libwolfpsa.a` has no Mbed TLS code. The tests link Mbed TLS's test
  certificate data.

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
