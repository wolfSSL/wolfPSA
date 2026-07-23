# Changelog

## Unreleased: PSA Certified Crypto API 1.4 + PQC extension 1.4

Upgrade of the public API surface and implementation to PSA Certified
Crypto API 1.4 Final and the PQC extension 1.4, built against current
wolfSSL master.

### Breaking changes

- ML-DSA now follows the PSA 1.4 PQC extension: key bits are 128/192/256
  (security strength, ML-DSA-44/65/87) instead of the previous 2/3/5
  level convention, and the key-pair import/export format is the 32-byte
  FIPS 204 seed xi (public keys remain raw pk bytes).
- The nonstandard `psa_ml_dsa_generate_key/sign/verify` exports and the
  `PSA_ML_DSA_PARAMETER_*` / `psa_ml_dsa_parameter_t` macros were removed;
  use the standard PSA key management and signature APIs instead.

### Added

- Key encapsulation: `psa_encapsulate()` / `psa_decapsulate()` with
  PSA_ALG_ML_KEM. ML-KEM key pairs use the 64-byte d||z seed format with
  bits 512/768/1024; the shared secret is returned as a new key.
- ML-DSA through the standard APIs: hedged and deterministic pure ML-DSA
  via `psa_sign_message`/`psa_verify_message`, plus HashML-DSA variants
  usable through both the message and hash entry points.
- Context-aware signatures: `psa_sign_message_with_context()`,
  `psa_verify_message_with_context()`, `psa_sign_hash_with_context()`,
  `psa_verify_hash_with_context()` and PSA_ALG_EDDSA_CTX (Ed25519ctx),
  with context support for Ed25519ph/Ed448 and the ML-DSA family.
- Verify-only LMS/HSS and XMSS/XMSS^MT public-key support through
  `psa_verify_message` (PSA_ALG_LMS/HSS/XMSS/XMSS_MT).
- XOF API: incremental SHAKE128/SHAKE256 via `psa_xof_setup/update/
  output/abort` (Ascon XOFs report NOT_SUPPORTED).
- Key wrapping: `psa_wrap_key()` / `psa_unwrap_key()` with PSA_ALG_KW
  (AES-KW, RFC 3394) and the new WRAP/UNWRAP usage flags (PSA_ALG_KWP
  reports NOT_SUPPORTED).
- Ascon-Hash256 and Ascon-AEAD128 (one-shot), XChaCha20-Poly1305
  (one-shot, 24-byte nonce) with the PSA_KEY_TYPE_XCHACHA20/ASCON key
  types.
- SP800-108r1 counter-mode KDFs: PSA_ALG_SP800_108_COUNTER_HMAC(hash)
  and PSA_ALG_SP800_108_COUNTER_CMAC.
- `psa_check_key_usage()`, `psa_generate_key_custom()` and
  `psa_key_derivation_output_key_custom()` (default parameters only).
- 1.4 semantic change: ECDSA and deterministic ECDSA are treated as
  equivalent when verifying signatures.
- Complete 1.4 macro surface: PQC classifier/encoding macros (ML-DSA,
  ML-KEM, SLH-DSA, LMS/HSS, XMSS), WPA3-SAE values, encapsulation and
  key-wrap size macros, hash-suspend format constants, and PQC arms in
  the signature/export size macros (PSA_SIGNATURE_MAX_SIZE is now 4627).
- Stubs returning PSA_ERROR_NOT_SUPPORTED for the interruptible
  operations, `psa_attach_key()` and `psa_hash_suspend/resume()`.
  SLH-DSA key types are recognized but report NOT_SUPPORTED.
- New coverage tests: ML-DSA, ML-KEM/KEM API, XOF, AES-KW, signature
  contexts, LMS/XMSS verify, Ascon/XChaCha, SP800-108 and 1.4 misc.
- `psa_purge_key()`: confirms a key exists and reports its status (wolfPSA
  keeps no in-RAM cache of persistent key material, so there is nothing to
  evict).
- Optional thread-safe key store: with `WOLFPSA_THREAD_SAFE` a single mutex
  built on wolfCrypt's portable `wc_*Mutex` API (created in `psa_crypto_init()`)
  guards the volatile-key list and id counter for concurrent PSA callers; a
  no-op in single-threaded builds.

### Zephyr module

- Added wolfPSA as a Zephyr **PSA Crypto provider**: selected via
  `CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM` (Zephyr >= 4.3), it supplies the PSA Crypto
  API in place of Mbed TLS while reusing the wolfCrypt core built by the wolfSSL
  Zephyr module. Volatile and persistent keys, RNG, and the standard PSA surface
  work with no Mbed TLS symbol in the image.
- wolfCrypt AES-256-GCM custom ITS transform
  (`CONFIG_SECURE_STORAGE_ITS_TRANSFORM_IMPLEMENTATION_CUSTOM`) provides
  encryption-at-rest for persistent keys, replacing Zephyr's Mbed-TLS-coupled
  AEAD transform. `psa_get_key_attributes()` restores the key id, for volatile
  keys too; key creation ignores that id when the lifetime is volatile, so the
  returned attributes stay usable as a key-creation template. Persistent keys
  use the crypto-provider ITS namespace (isolated from application
  `psa_its_*`/`psa_ps_*`).
- wolfPSA follows the user's wolfCrypt configuration and exposes exactly the
  enabled, wolfPSA-implemented algorithms as the PSA API.


## v5.9.1

Initial official release of `wolfPSA`. This project follows wolfSSL version numbering.

- First public wolfPSA release: a PSA Crypto engine implemented in C on top of wolfCrypt.
- Provides PSA Crypto API entry points intended for PSA clients such as wolfSSL built with `WOLFSSL_HAVE_PSA` and the Arm PSA Architecture Test Suite.
- Ships both static and shared builds: `libwolfpsa.a` and `libwolfpsa.so`.
- Includes core PSA lifecycle, random generation, key management, key storage, cipher, AEAD, hash, MAC, asymmetric crypto, key derivation, and TLS 1.3 PRF/HKDF support.
- Symmetric crypto coverage includes AES, ChaCha20, ChaCha20-Poly1305, and configured legacy compatibility paths such as DES/3DES where enabled.
- Hash and MAC support includes SHA-1, SHA-2, SHA-3, HMAC, CMAC, plus configured compatibility support for MD5 and RIPEMD-160.
- Asymmetric crypto support includes RSA, ECC/ECDSA/ECDH, Curve25519/Curve448, and Ed25519/Ed448.
- Includes persistent PSA key storage with a default POSIX filesystem-backed store for local and test deployments.
- Includes post-quantum and hash-based crypto integration sources for builds that enable wolfCrypt support, including ML-KEM, ML-DSA, LMS, and XMSS.
- Includes standalone integration tests and demos for PSA API calls, PSA-backed wolfCrypt benchmarking, and a TLS server/client flow using PSA-managed keys and certificate pinning.
- Includes target integration and scripts for running the Arm PSA Architecture Test Suite; current documented crypto results are 65 passed tests, 13 skipped, and 0 failed.
