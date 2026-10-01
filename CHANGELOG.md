# Changelog

## v5.9.4 (Oct 1, 2026)

PSA Certified Crypto API 1.4 + PQC extension 1.4, validated against wolfSSL v5.9.4-stable: unit tests, TLS client/server, wolfCrypt benchmark, the Arm PSA Architecture Test Suite and the Zephyr 4.3/4.4 samples run in CI against that tag and wolfSSL master.

Breaking changes

* ML-DSA follows the PSA 1.4 PQC extension: key bits are the security strength (128/192/256 = ML-DSA-44/65/87), key import/export is the 32-byte FIPS 204 seed xi, and the nonstandard psa_ml_dsa_* exports and PSA_ML_DSA_PARAMETER_* macros were removed in favor of the standard PSA APIs.
* Key derivation follows the PSA error-state rule: a failed call leaves the operation reporting PSA_ERROR_BAD_STATE until psa_key_derivation_abort(); set_capacity() no longer poisons the operation.
* wolfPSA_Store_Close() returns int so a failed commit reports WOLFPSA_STORE_IO_ERROR; out-of-tree WOLFPSA_CUSTOM_STORE backends must update the signature.
* psa_import_key() rejects zero-length blobs, ECC points whose length contradicts the curve, and Weierstrass keys that are not 0x04||X||Y of the exact length; unimplemented curves report PSA_ERROR_NOT_SUPPORTED.
* The POSIX store requires a private (non group/other-writable) store directory on the read path too, checking every ancestor.
* Requires wolfSSL >= 5.9.2 (ML-DSA moved to wc_mldsa.c); enable it with WOLFSSL_HAVE_MLDSA, not HAVE_DILITHIUM.
* Overlapping input/output buffers are refused in psa_cipher_encrypt()/decrypt() (IV modes) and psa_cipher_update() (block modes); in-place update still works for the stream modes.
* Multipart AEAD: psa_aead_update() returns output as it goes and finish/verify emit only the tag; AAD after the payload started is rejected with PSA_ERROR_BAD_STATE.
* Auto-assigned key ids come from the PSA vendor range; importing a persistent key over an existing id fails with PSA_ERROR_ALREADY_EXISTS; non-local storage lifetimes are rejected.
* Stricter key policies: KDF inputs require PSA_KEY_USAGE_DERIVE, key agreement checks the full policy algorithm, all requested usage bits are required, and PSA_ALG_ANY_HASH signature policies are honoured; psa_copy_key() accepts narrowing a wildcard policy.
* psa_import_key() checks declared bits against the data length for byte-string key types and refuses imports whose inferred bits overflow.
* Status code changes: empty or wrong-length signatures, tags and reference digests report PSA_ERROR_INVALID_SIGNATURE, a failed RSA unpad PSA_ERROR_INVALID_PADDING, an unsupported GCM nonce length PSA_ERROR_NOT_SUPPORTED, store allocation failures PSA_ERROR_INSUFFICIENT_MEMORY, and an unopenable store record PSA_ERROR_STORAGE_FAILURE.
* NULL zero-length buffers are accepted across the API and a zero-byte generation request succeeds.
* Shortened-tag ChaCha20-Poly1305/XChaCha20-Poly1305/Ascon are rejected at setup; Ed448 PureEdDSA rejects a non-empty context; TLS 1.2 PSK-to-MS caps PSKs at 128 bytes.

Added

* Key encapsulation: psa_encapsulate()/psa_decapsulate() with PSA_ALG_ML_KEM (64-byte d||z seed keys, 512/768/1024 bits, shared secret returned as a new key).
* ML-DSA through the standard APIs: hedged and deterministic pure ML-DSA plus HashML-DSA via the message and hash entry points.
* Context-aware signatures: the *_with_context() APIs, PSA_ALG_EDDSA_CTX (Ed25519ctx), and context support for Ed25519ph/Ed448 and the ML-DSA family.
* Verify-only LMS/HSS and XMSS/XMSS^MT public-key support.
* XOF API: incremental SHAKE128/SHAKE256 (Ascon XOFs report NOT_SUPPORTED).
* Key wrapping: psa_wrap_key()/psa_unwrap_key() with PSA_ALG_KW (AES-KW, RFC 3394) and the WRAP/UNWRAP usage flags.
* Ascon-Hash256 and Ascon-AEAD128 (one-shot), XChaCha20-Poly1305 (one-shot, 24-byte nonce).
* SP800-108r1 counter-mode KDFs: PSA_ALG_SP800_108_COUNTER_HMAC and _CMAC.
* psa_check_key_usage(), psa_generate_key_custom(), psa_key_derivation_output_key_custom() (default parameters).
* 1.4 semantics: ECDSA and deterministic ECDSA are equivalent on verify; complete 1.4 macro surface (PQC classifiers, WPA3-SAE, KEM/KW size macros; PSA_SIGNATURE_MAX_SIZE is now 4627).
* NOT_SUPPORTED stubs for the interruptible operations, psa_attach_key() and psa_hash_suspend/resume(); SLH-DSA key types are recognized.
* psa_purge_key() confirms a key exists and reports its status.
* Crypto callback offload extended to RSA, ECC, Ed25519/Ed448, X25519/X448, CMAC, HKDF, PBKDF2, the RNG and SHA-1/SHA-2, with wolfPSA_RegisterCryptoCb()/UnRegisterCryptoCb().
* Optional thread-safe key store with WOLFPSA_THREAD_SAFE.
* New coverage tests: ML-DSA, ML-KEM, XOF, AES-KW, signature contexts, LMS/XMSS verify, Ascon/XChaCha, SP800-108.

Security

* Side-channel hardening on by default: TFM_TIMING_RESISTANT, ECC_TIMING_RESISTANT and WC_RSA_BLINDING replace WC_NO_HARDEN.
* psa_import_key() rejects a data_length that would wrap the internal buffer size (heap overflow).
* ECC keys are pinned to their curve on import, verify, ECDH and export; secp256k1/Brainpool only with HAVE_ECC_KOBLITZ/HAVE_ECC_BRAINPOOL.
* Sensitive intermediates zeroized: cipher partial blocks and padded plaintext, CCM stack state, the multipart verify tag, KDF output on mid-stream error, export buffers on short read.
* A failed psa_copy_key() clears the target id; the interruptible max-ops setting is atomic.

Fixed

* RSA PKCS#1 v1.5 hashed verify compared the DigestInfo with the raw hash, so every valid signature failed.
* PBKDF2-AES-CMAC-PRF-128 normalized 16-byte passwords instead of using them directly (RFC 4615).
* The CCM counter increment lost its carry for nonces shorter than 13 bytes.
* The TLS 1.2 PRF KDFs passed the wrong MAC algorithm id to wc_PRF_TLS().
* OFB/CFB decryption keyed AES in the decrypt direction; both modes run the cipher forward.
* Ed25519ph/Ed448ph enforce a 64-byte prehash; SHAKE256-512 added for Ed448ph.
* Standalone EdDSA/Montgomery keygen and public-key export work without HAVE_ECC.
* A second psa_aead_set_lengths() reports PSA_ERROR_BAD_STATE; multipart AEAD length checks corrected.
* psa_hash_compare() rejects a NULL reference hash; generic ECDH reports NOT_SUPPORTED up front without an RNG.
* The HMAC path of psa_mac_* never called wc_HmacInit() and ran with devId 0.
* The one-shot AEAD paths freed uninitialized Aes objects when wc_AesInit() failed.

Build configuration

* AES backend policy (src/psa_config.h): builds fail unless AES is constant-time (WC_AES_BITSLICED, WOLFSSL_AES_TOUCH_LINES, or a hardware core); WOLFPSA_AES_FAST waives it. WC_AES_BITSLICED requires HAVE_AES_ECB and grows sizeof(Aes) to 123,296, so the Zephyr example selects WOLFSSL_AES_TOUCH_LINES.
* The one-shot AEAD Aes and the KDF Cmac objects moved from the stack to XMALLOC.
* WC_ALLOW_ECC_ZERO_HASH is required for HAVE_ECC builds, checked in the shared header.
* The multipart AEAD context holds GCM/CCM Aes in a union (sizeof 247,032 -> 123,736 under WC_AES_BITSLICED).
* make unit-run runs every unit and regression test; make cov produces an HTML gcov report.
* CI runs the regression suite, a build-configuration matrix, and every functional workflow against wolfSSL master and v5.9.4-stable.

Zephyr module

* wolfPSA as a Zephyr PSA Crypto provider (CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM, Zephyr >= 4.3): supplies the PSA Crypto API in place of Mbed TLS on top of the wolfSSL Zephyr module's wolfCrypt.
* AES-256-GCM custom ITS transform for persistent-key encryption-at-rest; persistent keys use the crypto-provider ITS namespace; psa_get_key_attributes() restores the key id.
* The module selects the constant-time AES backend and the ECC zero-hash allowance by default and exposes exactly the enabled, implemented algorithms.

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
