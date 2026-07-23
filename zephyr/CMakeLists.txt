# wolfPSA Zephyr module - PSA Crypto provider on top of wolfCrypt
#
# Copyright (C) 2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# wolfPSA compiles ONLY its own PSA frontend (src/*.c). The wolfCrypt core is
# provided by the sibling wolfSSL module: its headers are on the global include
# path and its compiled objects link into the final image, so wolfPSA resolves
# every wc_* symbol at final link with zero recompilation of wolfCrypt.

if(CONFIG_WOLFPSA)
  set(WOLFPSA_DIR ${ZEPHYR_CURRENT_MODULE_DIR})

  # Expose the PSA headers to the WHOLE build so that <psa/crypto.h> resolves
  # for every Zephyr consumer (BLE, TLS credentials, samples, ...). This is how
  # wolfPSA becomes THE system PSA provider, mirroring the mbedTLS interface
  # library's include propagation.
  #   ${WOLFPSA_DIR}         -> <wolfpsa/psa_engine.h>, <wolfpsa/psa/crypto.h>
  #   ${WOLFPSA_DIR}/wolfpsa -> <psa/crypto.h>, <psa_store.h>, <psa_key_storage.h>
  #
  # BEFORE (prepend): wolfPSA is THE PSA provider, so its psa/ headers must win
  # the global include order over any subsystem that ships a partial psa/ set.
  # In particular Zephyr's secure_storage subsystem ships a storage-only
  # <psa/error.h> guarded by the same PSA_ERROR_H; searched first it would
  # starve wolfPSA of the full PSA error set. wolfPSA's error codes are a
  # value-compatible superset, so secure_storage's own files still build.
  # (Storage-only headers wolfPSA does not provide -- <psa/storage_common.h>,
  # <psa/internal_trusted_storage.h> -- still resolve to secure_storage.)
  target_include_directories(zephyr_interface BEFORE INTERFACE
    ${WOLFPSA_DIR}
    ${WOLFPSA_DIR}/wolfpsa
  )

  # --- Build-time PSA surface generation (config-driven, Model B) ------------
  # wolfPSA exposes as the PSA API exactly the crypto that the user's wolfCrypt
  # configuration enabled (and that wolfPSA implements). We derive the
  # consumer-visible PSA_WANT_ surface from the ACTUAL compiled config by
  # preprocessing zephyr/gen/psa_want_probe.c and generating
  # crypto_config_zephyr.h, which <psa/crypto.h> -> crypto_config.h includes.
  # Generated at CONFIGURE time (autoconf.h already exists) so it is present
  # before any TU that includes <psa/crypto.h> compiles.
  if(DEFINED ZEPHYR_WOLFSSL_MODULE_DIR)
    set(_wolfssl_mod_dir ${ZEPHYR_WOLFSSL_MODULE_DIR})
  else()
    set(_wolfssl_mod_dir ${WOLFPSA_DIR}/../wolfssl)
  endif()
  if(DEFINED AUTOCONF_H)
    set(_wolfpsa_autoconf ${AUTOCONF_H})
  else()
    set(_wolfpsa_autoconf
      ${CMAKE_BINARY_DIR}/zephyr/include/generated/zephyr/autoconf.h)
  endif()

  set(WOLFPSA_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/wolfpsa_gen)
  set(WOLFPSA_GEN_HDR ${WOLFPSA_GEN_DIR}/crypto_config_zephyr.h)
  set(WOLFPSA_PROBE   ${WOLFPSA_DIR}/zephyr/gen/psa_want_probe.c)
  set(WOLFPSA_GEN_PY  ${WOLFPSA_DIR}/zephyr/gen/gen-crypto-config.py)
  file(MAKE_DIRECTORY ${WOLFPSA_GEN_DIR})

  set(_wolfpsa_probe_flags
    -D__ZEPHYR__=1 -DWOLFSSL_USER_SETTINGS -DWOLFSSL_ZEPHYR
    -I${WOLFPSA_DIR} -I${WOLFPSA_DIR}/wolfpsa
    -I${_wolfssl_mod_dir}/zephyr
    -imacros ${_wolfpsa_autoconf})
  # If the user supplied their own wolfCrypt config, the probe must see it too.
  if(CONFIG_WOLFSSL_SETTINGS_FILE)
    list(APPEND _wolfpsa_probe_flags
      "-DWOLFSSL_SETTINGS_FILE=\"${CONFIG_WOLFSSL_SETTINGS_FILE}\"")
  endif()

  execute_process(
    COMMAND ${PYTHON_EXECUTABLE} ${WOLFPSA_GEN_PY}
            ${WOLFPSA_GEN_HDR} ${CMAKE_C_COMPILER} ${WOLFPSA_PROBE}
            ${_wolfpsa_probe_flags}
    RESULT_VARIABLE _wolfpsa_gen_rc)
  if(NOT _wolfpsa_gen_rc EQUAL 0)
    message(FATAL_ERROR
      "wolfPSA: failed to generate the PSA_WANT surface (rc=${_wolfpsa_gen_rc})")
  endif()

  # The generated header wins because the checked-in one was removed; put its
  # dir on the global include path so <psa/crypto.h> -> crypto_config.h finds it.
  zephyr_include_directories(${WOLFPSA_GEN_DIR})

  # Re-run configure (and thus regenerate) when the config inputs change. The
  # effective wolfCrypt config now comes entirely from the wolfSSL module's
  # user_settings.h (plus the user's settings file, if any) -- wolfPSA no longer
  # provides a config of its own.
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    ${WOLFPSA_PROBE} ${WOLFPSA_GEN_PY}
    ${_wolfssl_mod_dir}/zephyr/user_settings.h)
  if(CONFIG_WOLFSSL_SETTINGS_FILE)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
      ${CONFIG_WOLFSSL_SETTINGS_FILE})
  endif()

  # Collect all PSA frontend sources, minus the POSIX store backend (replaced by
  # the Zephyr backend and disabled via WOLFPSA_CUSTOM_STORE).
  file(GLOB WOLFPSA_SOURCES ${WOLFPSA_DIR}/src/*.c)
  list(REMOVE_ITEM WOLFPSA_SOURCES ${WOLFPSA_DIR}/src/psa_store_posix.c)

  zephyr_library()
  zephyr_library_sources(${WOLFPSA_SOURCES})
  zephyr_library_sources(${WOLFPSA_DIR}/zephyr/zephyr_init.c)

  # wolfCrypt-backed custom ITS transform for the secure_storage subsystem.
  # Selecting the CUSTOM transform keeps Zephyr's Mbed-TLS-coupled aead.c out of
  # the build, so persistent-key storage encryption runs through wolfCrypt only.
  zephyr_library_sources_ifdef(CONFIG_SECURE_STORAGE_ITS_TRANSFORM_IMPLEMENTATION_CUSTOM
    ${WOLFPSA_DIR}/zephyr/src/psa_its_transform_wolfcrypt.c)

  # Internal headers ("psa_trace.h", "psa_size.h", *_internal.h) live in src/.
  zephyr_library_include_directories(${WOLFPSA_DIR}/src)

  # Select the pluggable store backend: our Zephyr implementation, not POSIX.
  zephyr_library_compile_definitions(WOLFPSA_CUSTOM_STORE)

  # WOLFSSL_PSA_ENGINE is the master gate for wolfPSA's own sources. Nothing in
  # the shared wolfCrypt library reads it, so it is defined ONLY for wolfPSA's
  # translation units here -- it is not part of the wolfCrypt config the module
  # builds against.
  zephyr_library_compile_definitions(WOLFSSL_PSA_ENGINE)

  # Inherit WOLFSSL_USER_SETTINGS + WOLFSSL_ZEPHYR and the wolfcrypt include
  # dirs from the wolfSSL module's interface library.
  zephyr_library_link_libraries(wolfSSL)
endif()
