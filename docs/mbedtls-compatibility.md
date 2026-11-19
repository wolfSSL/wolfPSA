# Mbed TLS compatibility

Details of the Mbed TLS 4.x API that `MBEDTLS_COMPAT=1` adds, and of the
TF-PSA-Crypto parts that every build has. See
[README.md](../README.md#mbed-tls-compatibility) to build and use it.

## Build and configuration

- wolfSSL's TLS sources are compiled from `WOLFSSL_PATH` into
  `libwolfpsa.a`, like wolfCrypt, with the TLS settings in `user_settings.h`.
  Changing the option rebuilds everything.
- The feature macros, such as `MBEDTLS_SSL_TLS_C`, `MBEDTLS_NET_C` and
  `MBEDTLS_PEM_PARSE_C`, are in the generated config in `build/include`, so
  a build without the option does not define them.
- The functions have the Mbed TLS names, so code that finds them by symbol
  name (`dlsym`, language bindings) works too.
- With `MBEDTLS_THREADING_C=1`, TLS is thread safe too.
- TLS uses wolfPSA's constant-time AES. `AES_FAST=1` applies to TLS too.
- As in Mbed TLS, certificates may have NULL parameters after an ECDSA
  signature OID, and serial number 0. This needs
  `WOLFSSL_ECC_SIGALG_PARAMS_NULL_ALLOWED` and `WOLFSSL_ASN_ALLOW_0_SERIAL`,
  which wolfPSA's `user_settings.h` defines. A build with its own
  `USER_SETTINGS_PATH` defines them too, or rejects such certificates, for
  example Mbed TLS's `test-ca2.crt` and `test-ca-any_policy.crt`.
- The X.509 API needs wolfCrypt's certificate parsing: without it (`NO_ASN`
  or `NO_CERTS`), `MBEDTLS_X509_CRT_PARSE_C` is not defined.
- `mbedtls_ssl_session_save` and `mbedtls_ssl_session_load` need
  `HAVE_EXT_CACHE`, which wolfPSA's `user_settings.h` defines. Without it,
  they return `MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE`. As TLS 1.3 resumes only
  with a ticket, `mbedtls_ssl_session_save` also returns it for a TLS 1.3
  session until the client, with `HAVE_SESSION_TICKET`, reads a ticket.
- TLS needs the X.509 API and wolfSSL's TLS with `HAVE_SNI`: without them,
  for example with `WOLFCRYPT_ONLY`, `MBEDTLS_SSL_TLS_C` is not defined.
  `MBEDTLS_NET_C` needs TLS and wolfSSL's socket I/O (no `WOLFSSL_USER_IO`).
  `MBEDTLS_PEM_PARSE_C` needs `MBEDTLS_BASE64_C`, which needs
  `WOLFSSL_BASE64_ENCODE`, defined in wolfPSA's `user_settings.h`.
- The verify callbacks need `WOLFSSL_ALWAYS_VERIFY_CB`, which wolfPSA's
  `user_settings.h` defines. A build with its own `USER_SETTINGS_PATH`
  defines it too.

## Currently supported

TLS:

- `mbedtls_ssl_config_*`: init, free, defaults
- `mbedtls_ssl_conf_*`: authmode, ca_chain, own_cert, min_tls_version,
  max_tls_version, ciphersuites, cert_profile, dbg, verify, endpoint,
  transport, get_endpoint, set_user_data_p, set_user_data_n,
  get_user_data_p, get_user_data_n
- `mbedtls_ssl_*`: init, free, setup, context_get_config, session_reset,
  set_bio, set_timer_cb, set_verify, set_hostname, set_session, get_session,
  handshake, is_handshake_over, get_verify_result, get_ciphersuite,
  get_ciphersuite_id_from_ssl, get_version, get_version_number,
  get_bytes_avail, read, write, close_notify, set_user_data_p,
  set_user_data_n, get_user_data_p, get_user_data_n
- Cipher suite lookup: `mbedtls_ssl_list_ciphersuites`,
  `mbedtls_ssl_get_ciphersuite_name`, `mbedtls_ssl_get_ciphersuite_id`
- `mbedtls_ssl_session_*`: init, free, save, load
- `mbedtls_ssl_conf_max_frag_len` and
  `mbedtls_ssl_get_max_out_record_payload`, with
  `MBEDTLS_SSL_MAX_FRAGMENT_LENGTH`
- `mbedtls_ssl_export_keying_material`, with
  `MBEDTLS_SSL_KEYING_MATERIAL_EXPORT`
- The two macros above need wolfSSL's `HAVE_MAX_FRAGMENT` and
  `HAVE_KEYING_MATERIAL`, which wolfPSA's `user_settings.h` defines.

X.509:

- `mbedtls_x509_crt_*`: init, free, parse, parse_der, parse_file,
  parse_path, get_ca_istrue, check_key_usage, check_extended_key_usage,
  has_ext_type
- `mbedtls_x509_*`: dn_gets, dn_get_next, serial_gets, time_is_past,
  time_is_future
- `mbedtls_x509_crt_profile_default`, `_next` and `_suiteb`, as names only

Other:

- `mbedtls_strerror`
- `mbedtls_net_*`: init, connect, bind, accept, close, free, recv, send,
  usleep
- `mbedtls_pem_*`: init, read_buffer, get_buffer, free
- `mbedtls_timing_*`: get_timer, set_delay, get_delay, get_final_delay
- `mbedtls_ms_time` and `mbedtls_time`
- The timers and `mbedtls_ms_time` use a monotonic clock.
  `MBEDTLS_TIMING_C` and `MBEDTLS_HAVE_TIME` need Windows or a Unix-like
  system.

TF-PSA-Crypto, in every build:

- `mbedtls_pk_*`: init, free, parse_key, parse_keyfile, parse_public_key,
  parse_public_keyfile, get_bitlen, can_do_psa. Private keys are RSA and EC,
  PEM or DER, traditional or PKCS #8. Public keys are RSA, EC, X25519 and
  X448, PEM or DER, SubjectPublicKeyInfo or, for RSA, PKCS #1. EC keys are
  on the curves the PSA engine has.
- `mbedtls_base64_*`: encode, decode
- `mbedtls/threading.h` with `MBEDTLS_THREADING_C`, on pthreads
- `mbedtls_psa_crypto_free`, `mbedtls_platform_zeroize` and
  `mbedtls/platform.h`

## Coming soon

TLS:

- Session tickets
- The peer certificate (`mbedtls_ssl_get_peer_cert`), for certificate
  pinning
- CRLs through `mbedtls_ssl_conf_ca_chain`
- ALPN (`mbedtls_ssl_conf_alpn_protocols`, `mbedtls_ssl_get_alpn_protocol`)
- PSK and opaque keys
- DTLS: timers, cookies, connection ID, renegotiation, context save and
  load, and UDP in `mbedtls_net_accept`
- RSA keys up to 4096 bits

X.509:

- `mbedtls_x509_crt_info` and `mbedtls_x509_crt_verify_info`
- `mbedtls_x509_crt_verify`
- CRL and CSR parsing (`mbedtls/x509_crl.h`, `mbedtls/x509_csr.h`)

Other:

- The rest of `mbedtls/pk.h`: key writing, sign and verify, PSA key
  wrapping
- `mbedtls/md.h`, `mbedtls/asn1.h`, `mbedtls/asn1write.h`,
  `mbedtls/nist_kw.h`, `mbedtls/psa_util.h` and `mbedtls/constant_time.h`
- Build files: pkg-config, a CMake package and Mbed TLS's library names
  (`libmbedtls`, `libmbedx509`, `libtfpsacrypto`)
- A Zephyr option for the compatibility layer

## Known differences from Mbed TLS

TLS:

- A config needs `mbedtls_ssl_config_defaults`. `mbedtls_ssl_conf_endpoint`
  and `mbedtls_ssl_conf_transport` cannot change the endpoint and transport
  it set: `mbedtls_ssl_setup` and the handshake then return
  `MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE`. wolfSSL makes its config for one
  endpoint and transport.
- A server's config needs its `mbedtls_ssl_conf_own_cert` before
  `mbedtls_ssl_setup`, which fails without it with
  `MBEDTLS_ERR_SSL_BAD_CONFIG`: wolfSSL makes a server connection only with
  a certificate and key.
- A second `mbedtls_ssl_conf_own_cert` replaces the first. Mbed TLS keeps
  both and picks one for each handshake. After a failed one,
  `mbedtls_ssl_setup` and the handshake return its error until one
  succeeds, where Mbed TLS keeps the certificates set before.
- A host name that wolfSSL does not take as a DNS name, such as `my_host`
  or `12345`, fails with `MBEDTLS_ERR_SSL_BAD_INPUT_DATA` from
  `mbedtls_ssl_set_hostname`, or from `mbedtls_ssl_setup` when set before
  it. Mbed TLS takes any name of up to 255 characters.
- `mbedtls_ssl_set_hostname` during a handshake applies from the next
  `mbedtls_ssl_session_reset`. Mbed TLS uses the new name for the rest of
  that handshake.
- A saved session has an 8-byte header, the 4-byte verify result, then
  wolfSSL's session data. The header has a format number, the wolfSSL
  version, the wolfSSL build options that change the data and the sizes of
  its hash fields, so a session saved by Mbed TLS, with another format, or by
  another wolfSSL release or build, fails to load with
  `MBEDTLS_ERR_SSL_VERSION_MISMATCH`. wolfSSL development builds between
  releases can have the same version and other session data. The header
  does not tell those apart, and loading fails with
  `MBEDTLS_ERR_SSL_BAD_INPUT_DATA` when the data's length differs.
- `mbedtls_ssl_session_load` returns `MBEDTLS_ERR_SSL_BAD_INPUT_DATA` when
  wolfSSL fails to allocate the session, since wolfSSL's decoder does not
  say why it failed.
- A server resumes sessions from wolfSSL's session cache, where Mbed TLS
  needs `mbedtls_ssl_conf_session_cache`. A server that verifies client
  certificates reports `MBEDTLS_X509_BADCERT_MISSING` for a resumed session.
- `mbedtls_ssl_export_keying_material` takes shorter inputs, as wolfSSL's
  key derivation limits them: in TLS 1.2 a label of at most 64 bytes, or 62
  for the label and context together; in TLS 1.3 a label of at most 53
  bytes (69 with a SHA-256 cipher suite) and a context of at most 65535.
  Longer ones return `MBEDTLS_ERR_SSL_BAD_INPUT_DATA`, as do labels that
  start with one of the TLS 1.2 key schedule's, such as `master secret`.
- With `MBEDTLS_SSL_KEYING_MATERIAL_EXPORT`, each connection keeps wolfSSL's
  handshake secrets and randoms, among them the TLS 1.3 master secret, until
  it is freed or reset. Mbed TLS keeps only what the export needs.
- In TLS 1.3, a client sends the max fragment length extension, and a
  server sends records of at most the length its client asks for. Mbed TLS
  uses the extension in TLS 1.2 only.
- `mbedtls_ssl_conf_dbg` and `mbedtls_ssl_conf_cert_profile` are accepted
  and ignored.
- `mbedtls_net_accept` is TCP only.

Certificate verification:

- The verify flags come from wolfSSL, which reports one failure from each
  certificate's signature and date checks, and one from the later checks of
  the peer's own, such as the host name. So the verify callback and
  `mbedtls_ssl_get_verify_result` can report fewer flags than Mbed TLS: an
  untrusted certificate that has also expired is only `NOT_TRUSTED`.
- The verify callback gets the certificates the peer sent, in that order,
  then above them the CA from the CA list that issued the last one. Mbed TLS
  builds the chain itself, and leaves out a certificate the peer sent once
  it reaches a CA from the list.
- `mbedtls_ssl_conf_ca_chain` refuses a CRL: `mbedtls_ssl_setup` and the
  handshake then return `MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE` until a CA
  list without one is set.
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
  of a certificate without SANs. It is not sent as the server name, which
  RFC 6066 does not allow and Mbed TLS does.
- A DNS SAN with a wildcard in part of its first label, such as `r*` or
  `r*.example.com`, matches `router` or `router.example.com`. Mbed TLS
  takes a wildcard only as a whole first label, as in `*.example.com`.
- A trailing dot in the host name or a DNS SAN is ignored, so `router.`
  matches `router`. Mbed TLS compares the names as they are.
- wolfSSL keeps the intermediate CAs of a chain that verifies, for the
  config's later handshakes. A peer that then leaves them out still
  verifies, where Mbed TLS reports `NOT_TRUSTED`.

X.509:

- `mbedtls_x509_crt` has the parsed fields, but not `pk`. A certificate
  that wolfCrypt rejects returns
  `MBEDTLS_ERR_X509_INVALID_FORMAT`, where Mbed TLS often returns a more
  specific error.
- With `NO_ASN_TIME`, `mbedtls_x509_time_is_past` and
  `mbedtls_x509_time_is_future` return 0, as Mbed TLS does without
  `MBEDTLS_HAVE_TIME_DATE`.
- `mbedtls_x509_crt_parse_path` needs `<dirent.h>`. On Windows, or with
  `NO_WOLFSSL_DIR`, it returns `MBEDTLS_ERR_X509_FILE_IO_ERROR`.
- The profiles are not applied: wolfSSL's own limits hold.
  `mbedtls_x509_crt_profile` is opaque, so applications cannot define their
  own.
- wolfSSL parses some certificates differently. For example, it rejects a
  pathlen above `WOLFSSL_MAX_PATH_LEN` and accepts spaces in PEM.

Other:

- A wolfSSL error with no Mbed TLS match returns a general code for the
  call, such as `MBEDTLS_ERR_SSL_INTERNAL_ERROR`. wolfSSL's own codes are not
  returned: some Mbed TLS 4.x codes are PSA values (-128 to -160), which
  overlap wolfCrypt codes.
- `mbedtls_strerror` also describes the codes of TF-PSA-Crypto's modules,
  such as `MBEDTLS_ERR_PK_FILE_IO_ERROR`, which Mbed TLS 4.x reports as
  unknown. As in Mbed TLS, PSA codes, and the codes that are PSA values such
  as `MBEDTLS_ERR_SSL_BAD_INPUT_DATA`, are unknown.
- `mbedtls_pem_read_buffer` returns `MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE`
  for encrypted PEM. No `mbedtls_pem_write_buffer`.
- `mbedtls_base64_encode` is not constant time.
- `mbedtls_pk_parse_key` and `mbedtls_pk_parse_public_key` do not take
  encrypted keys or EC keys with a compressed public key.
- No global mutexes such as `mbedtls_threading_gmtime_mutex`.

## Tests

```
make MBEDTLS_COMPAT=1 mbedtls-compat-test
```

runs these against `libwolfpsa.a`. Each is also a target of its own;
`make help` lists them all.

- `mbedtls-compat-unit`: `test/mbedtls_compat/error_test.c` checks
  `mbedtls_strerror`. `x509_crt_test.c`, `pk_test.c` and `pem_test.c` parse
  Mbed TLS's test certificates and keys. `ssl_test.c` checks return codes,
  verify results and the verify callbacks, client and server in one
  process. `timing_test.c` checks the timers and `mbedtls_ms_time`.
- `mbedtls-compat-programs`: the Mbed TLS migration guide client
  (`test/mbedtls_compat/client-tls-mbedtls.c`) and Mbed TLS's sample
  programs, built unchanged. The clients run against the wolfSSL example
  server and the servers against the wolfSSL example client and
  `ssl_client1`. `load_roots` needs neither. With `MBEDTLS_THREADING_C=1`,
  `ssl_pthread_server` serves clients at the same time.
- `mbedtls-compat-suite`: Mbed TLS's TLS unit tests, the cases that test
  the public API (below).

Notes:

- The tests clone Mbed TLS at `MBEDTLS_REF` (set in
  `test/mbedtls_compat/Makefile`) into the build directory, so the first
  run needs network access. `MBEDTLS_PATH` uses an Mbed TLS 4.x checkout
  with its `framework` and `tf-psa-crypto` submodules instead, for unit and
  programs. The suite always uses the clone, since it changes it.
- The example server and client come from a wolfSSL configured out of tree
  from `WOLFSSL_PATH`, which must not be configured in place. The tests use
  the certificates in its `certs/`. This needs autoconf, automake and
  libtool.
- Also needs python3 with jinja2. Without faketime, the case that needs it
  is skipped.
- `WRAP` prefixes each test program, for example `WRAP=valgrind`. Server
  programs are stopped by the script, so their exit codes are not checked.
- `libwolfpsa.a` has no Mbed TLS code. The tests link Mbed TLS's test
  certificate data, and the suite its test code, changed by
  `test/mbedtls_compat/ssl_suite/mbedtls.patch` (Mbed TLS's license).

### mbedtls-compat-suite

Most of Mbed TLS's TLS unit tests check its internals: the record layer,
the handshake state machine, the key schedule. `mbedtls-compat-suite` runs
the cases whose test logic uses the public API. `ssl_suite/cases.txt`
lists them, each with its test function and the result it should have:
pass; fail, with the feature it waits on; or not run, with the reason.
The target prints how many pass and what the rest wait on, and fails when
a result differs. A case that passes where fail is listed is an error too,
so the change that adds a feature also marks its cases pass.

- Mbed TLS's test helpers (`ssl_helpers.c`) reach its internals.
  `mbedtls.patch` turns those parts off and `ssl_helpers_port.c` does the
  same through the public API. For example, the session the save and load
  cases use comes from a handshake, where Mbed TLS's helper sets its
  fields.
- `mbedtls-compat-suite-ref` runs the same cases on Mbed TLS's own
  libraries, built from the clone with CMake, and every case must pass.
  This shows the changed helpers still test what Mbed TLS's do. It needs
  no wolfSSL, but needs cmake and python3 with jinja2 and jsonschema.
- To change the patch, edit the clone (`build/mbedtls_compat/mbedtls` by
  default), then run `make MBEDTLS_COMPAT=1 mbedtls-compat-suite-patch`. A
  newer `mbedtls.patch` resets the clone, dropping edits made there.
- After a change of `MBEDTLS_REF`, the suite build fails when `cases.txt`
  lists a case Mbed TLS dropped, or lacks a new case of a test function it
  uses. If the patch does not apply, `git apply --reject` in the clone
  leaves the parts that fail in `.rej` files; fix them, then save the
  patch.
