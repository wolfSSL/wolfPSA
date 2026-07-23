# wolfPSA as a Zephyr PSA Crypto provider

This directory makes wolfPSA a Zephyr module that provides the PSA Crypto API
(replacing the Mbed TLS provider), reusing the wolfCrypt core built by the
sibling wolfSSL Zephyr module. See the "Second build path: Zephyr module"
section of `../CLAUDE.md` for the architecture.

## Requirements

- **Zephyr 4.3 or newer.** wolfPSA plugs into Zephyr's pluggable PSA Crypto
  provider choice (`CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM`), which was introduced in
  **Zephyr 4.3**. On older Zephyr that Kconfig symbol does not exist, so
  `CONFIG_WOLFPSA` can never be enabled and the module is inert -- there is no
  extension point to plug into. Persistent keys additionally use the
  `secure_storage` subsystem (Zephyr 4.0+), which the 4.3 floor already covers.
- **Tested on Zephyr 4.3 and 4.4** (CI builds and runs the samples/tests on
  native_sim for both).

(This floor is specific to wolfPSA-as-a-PSA-provider. The sibling wolfSSL module
that supplies the wolfCrypt core is a plain library and supports a much wider
Zephyr range.)

## Enabling wolfPSA in an application

In `prj.conf`:

```
CONFIG_WOLFSSL=y                      # wolfCrypt core (not auto-selected; see Kconfig)
CONFIG_PSA_CRYPTO=y
CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM=y   # selects wolfPSA (CONFIG_WOLFPSA defaults y)
CONFIG_ENTROPY_GENERATOR=y            # DRBG seed source; auto-enables CSPRNG_ENABLED
```

You do not set `CONFIG_WOLFPSA` yourself: `CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM=y`
auto-selects it (it defaults `y`). It is the symbol that gates every wolfPSA
source, so it is the one to reference from your own Kconfig (`depends on WOLFPSA`)
if needed.

`CONFIG_ENTROPY_GENERATOR=y` is enough to have wolfPSA seed the DRBG from the
platform CSPRNG (`sys_csrand_get`): it pulls in the entropy driver, and
`CONFIG_CSPRNG_ENABLED` is then `default y`. Avoid `CONFIG_CSPRNG_NEEDED` -- that
request symbol only exists in Zephyr 4.4+ and aborts the Kconfig parse on 4.3.

RNG interplay with the wolfSSL module: wolfPSA reuses the single wolfCrypt core
built by the wolfSSL module, so there is ONE wolfCrypt HashDRBG shared by both --
not a separate wolfPSA RNG. wolfPSA's boot init registers the Zephyr-CSPRNG seed
callback so that shared DRBG is seeded from Zephyr's entropy source (the
platform's hardware TRNG / entropy driver via `sys_csrand_get`).

## Configuring which crypto wolfPSA exposes

wolfPSA owns **no** wolfCrypt configuration of its own. It follows whatever the
wolfSSL module was built with and exposes exactly the enabled (and
wolfPSA-implemented) algorithms as the PSA API. You configure wolfCrypt the
normal wolfSSL way -- either the module's Kconfig options, or your own settings
file:

```
CONFIG_WOLFSSL_SETTINGS_FILE="/abs/path/to/my_user_settings.h"
```

The consumer-visible `PSA_WANT_*` surface is generated from the resulting
compiled config at build time; enabling fewer wolfCrypt features shrinks both the
PSA surface and the image, and an app that requests a family you did not enable
gets an honest compile-time miss. A ready-made broad example config is provided
at `zephyr/user_settings_example.h` (opt in with
`CONFIG_WOLFSSL_SETTINGS_FILE="zephyr/user_settings_example.h"`); the samples/tests use
it. (Realistic reductions -- dropping asymmetric families, PQC, curves, or
RSA/ECC -- are supported; dropping the symmetric core is not yet guarded.)

The only wolfCrypt profile wolfPSA imposes is structural, and it is applied
through generic wolfSSL Kconfig knobs the wolfPSA Kconfig `select`s
(`WOLFSSL_HASH_DRBG`, `WOLFSSL_RNG_SEED_CB`, and `WOLFSSL_SINGLE_THREADED` on a
no-threads kernel) -- the wolfSSL module stays entirely wolfPSA-unaware, and
`WOLFSSL_PSA_ENGINE` is defined only for wolfPSA's own sources. `WOLFSSL_CRYPTO_ONLY`
is NOT among them: crypto-only versus TLS coexistence is a user choice (see below),
not a wolfPSA requirement.

### Coexisting with the wolfSSL TLS stack

Whether the wolfSSL TLS layer is in the build is a wolfCrypt-config decision, not
a wolfPSA one -- wolfPSA works crypto-only or alongside TLS without any knob of
its own:

- **Crypto-only** (no TLS): set `CONFIG_WOLFSSL_CRYPTO_ONLY=y` (or use a
  `WOLFCRYPT_ONLY` settings file). This is what the samples/tests do.
- **TLS + wolfPSA in one image**: leave `WOLFCRYPT_ONLY` off and use a
  TLS-capable wolfCrypt config (e.g. the module's default -- do NOT point
  `CONFIG_WOLFSSL_SETTINGS_FILE` at the crypto-only example), then configure TLS
  features the usual way (`WOLFSSL_TLS_*`, cipher suites, ...).

wolfCrypt is shared by both layers, so there is no duplication, and the TLS layer
keeps calling wolfCrypt **directly** -- it does not route its crypto through the
PSA interface (`WOLFSSL_HAVE_PSA` stays off). `zephyr/tests/psa_tls_coexist`
builds exactly this: it runs a TLS handshake and PSA operations together in one
image. (The TLS layer's socket I/O pulls in the Zephyr networking stack.)

## Persistent keys (secure_storage)

Volatile keys work with the config above. For **persistent** keys, wolfPSA backs
the PSA store with the Zephyr `secure_storage` subsystem (the same PSA ITS path
Mbed TLS uses), with **no Mbed TLS in the image**:

- `src/psa_store_zephyr.c` maps the `wolfPSA_Store_*` backend onto the PSA ITS API
  (`psa_its_set`/`get`/`get_info`/`remove`) when `CONFIG_SECURE_STORAGE` is set
  (otherwise it stays a volatile-only stub).
- `zephyr/src/psa_its_transform_wolfcrypt.c` is a wolfCrypt **AES-256-GCM** custom
  ITS transform, selected with `CONFIG_SECURE_STORAGE_ITS_TRANSFORM_IMPLEMENTATION_CUSTOM`.
  This replaces Zephyr's stock AEAD transform, which is hardwired to Mbed TLS core
  internals (`psa_driver_wrapper_*`, `mbedtls_platform_zeroize`) and would not link
  in a wolfPSA build.

Add to `prj.conf` (on top of the base config), choosing a store backend
(`SETTINGS` shown; `ZMS` also works):

```
CONFIG_SECURE_STORAGE=y
CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_SETTINGS=y
CONFIG_SECURE_STORAGE_ITS_TRANSFORM_IMPLEMENTATION_CUSTOM=y
CONFIG_SETTINGS=y
CONFIG_SETTINGS_NVS=y
CONFIG_NVS=y
CONFIG_FLASH=y
CONFIG_FLASH_MAP=y
# AES-GCM for the transform (wolfPSA defaults OUTPUT_OVERHEAD to 28 for you):
CONFIG_PSA_WANT_KEY_TYPE_AES=y
CONFIG_PSA_WANT_ALG_GCM=y
```

Validated by running Zephyr's own `samples/psa/persistent_key`, `samples/psa/its`
and `tests/subsys/secure_storage/psa/crypto` against wolfPSA (the `psa_its`,
`psa_persistent_key` and `psa_secure_storage` wrappers), plus the `psa_transform`
unit test.

### Security considerations for at-rest encryption

The AES-256-GCM ITS transform protects confidentiality and integrity, but its
strength is bounded by two properties it inherits from the platform, the same as
Zephyr's stock transform:

- **The key is derived from the device id, which is not necessarily secret.** On
  a target with `CONFIG_HWINFO`, the per-entry key is `SHA-256(device-id || uid)`.
  The device id may be easily readable by an attacker, not unique, and/or
  guessable, depending on the device, so this is functional protection, not a
  guarantee. Without `CONFIG_HWINFO` the derivation falls back to a fixed
  constant and is not device-unique at all. For production, provision a
  hardware-backed key (secure element, protected fuse, or a TF-M-held key)
  rather than relying on the device id.
- **There is no rollback (anti-replay) protection.** The GCM AAD binds the entry
  UID and create-flags, so a record cannot be substituted across UIDs or flags,
  but it carries no version or counter. An attacker with access to the backing
  store can therefore restore an older ciphertext for the same UID and it will
  still authenticate. Anti-rollback requires trusted monotonic state (for
  example an RPMB, a monotonic counter, or TF-M) that this layer does not have.
  Account for this where the stored data feeds attestation or other monotonic
  guarantees.

## Module discovery

The recommended way is to add wolfPSA as a project in your workspace's
`manifest/west.yml`, exactly like the wolfSSL module, so `west update` pulls it
in and it is discovered automatically (no extra build flags needed):

```yaml
    - name: wolfpsa
      path: modules/crypto/wolfpsa
      revision: <branch-or-tag>
      # remote: <your remote>
```

CI does not use a checked-in manifest: `.github/scripts/zephyr-4.x/zephyr-test.sh`
runs its own `west init` and injects the wolfSSL and wolfPSA module entries.

Alternatively, for an out-of-manifest checkout, point the build at the module
explicitly with `EXTRA_ZEPHYR_MODULES` (absolute path to the wolfPSA repo root):

```sh
# host is aarch64 here -> use the 64-bit native_sim variant
WOLFPSA=$(cd .. && pwd)          # wolfPSA repo root (the dir containing zephyr/)
```

## Build & run the samples (native_sim)

```sh
cd <west-workspace-root>          # e.g. /home/tobi/wolfssl/zephyr
west build -p always -b native_sim/native/64 -d build-x \
  "$WOLFPSA/zephyr/samples/psa_smoke" -- -DEXTRA_ZEPHYR_MODULES="$WOLFPSA"
# native_sim block-buffers piped stdout; force line-buffering to see logs:
stdbuf -oL -eL ./build-x/zephyr/zephyr.exe
```

Sample: `samples/psa_smoke` -- a broad capability smoke
(hashes/MAC/AES/RSA/ECDSA/ECDH/ML-KEM/ML-DSA).

## Run the samples and tests

The simplest way (and what CI uses) is the helper script, run from inside the
west workspace -- it builds and runs every sample and test on native_sim and
prints a pass/fail summary:

```sh
cd <west-workspace-root>                    # e.g. /home/tobi/wolfssl/zephyr
"$WOLFPSA/.github/scripts/run-tests.sh"     # exits non-zero on any failure
```

CI (`.github/workflows/zephyr-4.x.yml`) runs the same script across a Zephyr 4.x
matrix via the Docker driver `.github/scripts/zephyr-4.x/zephyr-test.sh`,
mirroring the wolfSSL module's Zephyr CI.

To run the ztests through twister instead, pass the module as a CMake extra
arg with twister's `-x` flag (there is no `--extra-module`/`--west-flags`
option):

```sh
cd <west-workspace-root>
west twister -p native_sim/native/64 \
  -T "$WOLFPSA/zephyr/tests" \
  -x=EXTRA_ZEPHYR_MODULES="$WOLFPSA"
```

Tests are (a) thin **wrappers that run Zephyr's OWN provider-agnostic apps
against wolfPSA** (the drop-in proof, reusing their source from `$ZEPHYR_BASE`)
and (b) checks of wolfPSA-internal behavior Zephyr cannot cover:
- `tests/psa_consumer` -- Zephyr's `tests/crypto/mbedtls_psa` source, unchanged.
- `tests/psa_its` -- Zephyr's `samples/psa/its`.
- `tests/psa_persistent_key` -- Zephyr's `samples/psa/persistent_key`.
- `tests/psa_secure_storage` -- Zephyr's `tests/subsys/secure_storage/psa/crypto`
  (persistent key + ITS + PS caller isolation).
- `tests/psa_concurrency` -- wolfPSA's key-store lock (no Zephyr equivalent).
- `tests/psa_entropy` -- seed-failure -> `PSA_ERROR_INSUFFICIENT_ENTROPY`.
- `tests/psa_transform` -- wolfCrypt AES-GCM ITS transform confidentiality /
  tamper / UID-binding (Zephyr's custom-transform test is a plaintext passthrough).
- `tests/psa_tls_coexist` -- a wolfSSL TLS handshake and PSA operations in one
  image (the TLS layer and the provider coexist; TLS is not made crypto-only).

For CI/production, add a `wolfpsa` project to `manifest/west.yml` (path
`modules/crypto/wolfpsa`) so the module is discovered without `EXTRA_ZEPHYR_MODULES`.

