WOLFPSA_PATH ?= ..
WOLFSSL_PATH ?= $(WOLFPSA_PATH)/../wolfssl
WOLFPSA_ABS := $(abspath $(WOLFPSA_PATH))
BUILD_DIR ?= build

WOLFSSL_CANDIDATE_DIRS := \
	$(WOLFSSL_PATH)/build \
	$(WOLFSSL_PATH)/src/.libs \
	$(WOLFSSL_PATH)

WOLFSSL_BUILD_DIR ?= $(firstword $(foreach dir,$(WOLFSSL_CANDIDATE_DIRS),\
	$(if $(wildcard $(dir)/libwolfssl.so $(dir)/libwolfssl.a),$(dir))))

CC ?= cc
NM ?= nm

CFLAGS ?= -O2
WARNFLAGS ?= -Wall -Wextra -Werror
CFLAGS += $(WARNFLAGS)
DEBUG_FLAGS :=
ifeq ($(DEBUG),1)
DEBUG_FLAGS = -ggdb
endif
SANITIZE_FLAGS :=
ifeq ($(ASAN),1)
SANITIZE_FLAGS = -fsanitize=address
endif
CFLAGS += $(DEBUG_FLAGS) $(SANITIZE_FLAGS)
LDFLAGS += $(SANITIZE_FLAGS)

# gcov coverage (make cov): instrument the test binaries too, so the
# crypto-callback and probe sub-builds (which inherit CFLAGS) are covered.
ifeq ($(COV),1)
CFLAGS += --coverage
LDFLAGS += --coverage
endif

# The ECC curve regression tests read the library's feature macros
# (they include <user_settings.h> and branch on HAVE_ECC_KOBLITZ /
# HAVE_ECC_BRAINPOOL), so only they mirror the library build:
# -DWOLFSSL_USER_SETTINGS plus USER_SETTINGS_PATH, which takes the same
# value as the library build and by default resolves to the repository
# root, which ships the baseline user_settings.h. The flag and the
# include path stay out of the shared CPPFLAGS on purpose: every other
# test TU links the autotools-built libwolfssl and must see that
# library's own configuration (config.h, via HAVE_CONFIG_H) - layering
# wolfPSA's user_settings.h on top would let a test declare wolfCrypt
# structs (Hmac, wc_Sha256) with a layout the linked library does not
# use.
USER_SETTINGS_PATH ?= $(WOLFPSA_PATH)
WOLFSSL_CPPFLAGS ?= -DWOLFSSL_USER_SETTINGS

CPPFLAGS += -DHAVE_CONFIG_H -DWOLFSSL_HAVE_PSA -DHAVE_PK_CALLBACKS
CPPFLAGS += -I$(WOLFSSL_PATH) -I$(WOLFSSL_PATH)/wolfssl
ifneq ($(WOLFSSL_BUILD_DIR),)
CPPFLAGS += -I$(WOLFSSL_BUILD_DIR)
endif
CPPFLAGS += -I$(WOLFPSA_PATH) -I$(WOLFPSA_PATH)/wolfpsa
CPPFLAGS += -I$(WOLFPSA_PATH)/src
CPPFLAGS += -I$(WOLFPSA_PATH)/test/psa_server

LDFLAGS += -L$(WOLFPSA_PATH)
ifneq ($(WOLFSSL_BUILD_DIR),)
LDFLAGS += -L$(WOLFSSL_BUILD_DIR)
endif
LDLIBS += -lwolfssl -lwolfpsa -lpthread -lm

RPATH_WOLFPSA = -Wl,-rpath,'$$ORIGIN/..'
RPATH_WOLFSSL =
ifneq ($(WOLFSSL_BUILD_DIR),)
RPATH_WOLFSSL = -Wl,-rpath,$(abspath $(WOLFSSL_BUILD_DIR))
endif

WOLFSSL_LOCAL_LIB := $(firstword \
	$(wildcard $(WOLFSSL_BUILD_DIR)/libwolfssl.so) \
	$(wildcard $(WOLFSSL_BUILD_DIR)/libwolfssl.a))
WOLFSSL_LOCAL_SYMBOLS := $(if $(WOLFSSL_LOCAL_LIB),$(shell \
	$(NM) -D $(WOLFSSL_LOCAL_LIB) 2>/dev/null || \
	$(NM) $(WOLFSSL_LOCAL_LIB) 2>/dev/null))
WOLFSSL_HAS_PSA_TLS := $(findstring wolfSSL_CTX_psa_enable,$(WOLFSSL_LOCAL_SYMBOLS))

BINARIES = psa_api_test psa_crypto_init_test psa_des3_stack_scrub_test psa_ecc_bit_inference_test psa_ecc_curve_id_test psa_random_size_test psa_rsa_pss_interop_test psa_mldsa_test psa_mlkem_test psa_xof_test psa_key_wrap_test psa_sign_context_test psa_lms_xmss_verify_test psa_ascon_xchacha_test psa_sp800_108_test psa_14_misc_test psa_tls_client wolfcrypt-psa-benchmark

# PSA 1.4 coverage tests: one self-contained binary per feature area, all
# built from psa_server/<name>.c with the default link recipe.
PSA_14_TESTS = psa_mldsa_test psa_mlkem_test psa_xof_test psa_key_wrap_test \
	psa_sign_context_test psa_lms_xmss_verify_test psa_ascon_xchacha_test \
	psa_sp800_108_test psa_14_misc_test

# Regression tests: one self-contained binary per finding, all
# built from psa_server/<name>.c with the default link recipe.
PSA_REGRESSION_TESTS = psa_aead_multipart_test \
	psa_copy_key_narrowing_test \
	psa_xof_input_wrap_test \
	psa_pbkdf2_cmac_test \
	psa_kdf_input_key_test \
	psa_ecc_verify_curve_test \
	psa_ecc_ecdh_curve_test \
	psa_xof_output_wrap_test \
	psa_kdf_length_check_test \
	psa_kdf_expand_context_test \
	psa_kdf_error_state_test \
	psa_kdf_repeat_step_test \
	psa_kdf_psk_to_ms_size_test \
	psa_mldsa_det_sign_test \
	psa_mldsa_any_hash_test \
	psa_ecc_curve_caps_test \
	psa_xof_no_backend_test \
	psa_ecc_sig_len_test \
	psa_xof_set_context_test \
	psa_cipher_inplace_test \
	psa_cipher_overlap_test \
	psa_des3_pkcs7_test \
	psa_eddsa_mont_export_test \
	psa_eddsa_mont_gen_test \
	psa_pure_eddsa_context_test \
	psa_sign_hash_eddsa_test \
	psa_key_infer_bits_test \
	psa_cipher_oneshot_len_test \
	psa_pqc_export_seed_test \
	psa_key_declared_bits_test \
	psa_store_read_open_test \
	psa_store_dir_validation_test \
	psa_import_zero_length_test \
	psa_copy_key_cross_lifetime_test \
	psa_zero_capacity_buffer_test
BINARIES += $(PSA_REGRESSION_TESTS)

# Regression test with a custom link: it replaces the store backend, so it
# cannot use the recipe above (see PROBE_LIB below).
BINARIES += psa_import_key_probe_test

ifdef WOLFSSL_HAS_PSA_TLS
BINARIES += psa_tls_server
endif

PSA_API_TEST_OBJS = psa_server/psa_api_test.o
PSA_CRYPTO_INIT_TEST_OBJS = psa_server/psa_crypto_init_test.o
PSA_DES3_STACK_SCRUB_TEST_OBJS = psa_server/psa_des3_stack_scrub_test.o
PSA_ECC_BIT_INFERENCE_TEST_OBJS = psa_server/psa_ecc_bit_inference_test.o
PSA_ECC_CURVE_ID_TEST_OBJS = psa_server/psa_ecc_curve_id_test.o
PSA_RANDOM_SIZE_TEST_OBJS = psa_server/psa_random_size_test.o
PSA_ECC_CURVE_ID_TEST_DEPS = $(WOLFPSA_PATH)/$(BUILD_DIR)/obj/psa_asymmetric.o \
	$(WOLFPSA_PATH)/$(BUILD_DIR)/obj/psa_pq.o
PSA_RSA_PSS_TEST_OBJS = psa_server/psa_rsa_pss_interop_test.o

.PHONY: all clean rebuild-wolfssl-psa require-wolfssl-lib FORCE

all: info $(BINARIES)

info:
ifndef WOLFSSL_LOCAL_LIB
	@echo "Skipping psa_tls_server: no local wolfSSL library found under $(WOLFSSL_PATH) (checked: $(WOLFSSL_CANDIDATE_DIRS)). Build wolfSSL first, for example: make -C $(WOLFSSL_PATH)"
else ifndef WOLFSSL_HAS_PSA_TLS
	@echo "Skipping psa_tls_server: $(WOLFSSL_LOCAL_LIB) does not export wolfSSL PSA TLS callback symbols (for example wolfSSL_CTX_psa_enable). If you want to rebuild the sibling wolfSSL tree for wolfPSA, run: make rebuild-wolfssl-psa"
endif

psa_api_test: require-wolfssl-lib $(PSA_API_TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(PSA_API_TEST_OBJS) $(LDFLAGS) $(LDLIBS) $(RPATH_WOLFPSA) $(RPATH_WOLFSSL)

psa_crypto_init_test: require-wolfssl-lib $(PSA_CRYPTO_INIT_TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(PSA_CRYPTO_INIT_TEST_OBJS) $(WOLFPSA_PATH)/libwolfpsa.a $(LDFLAGS) -lwolfssl -lpthread -lm $(RPATH_WOLFSSL) -Wl,--wrap=wolfCrypt_Init

psa_des3_stack_scrub_test: require-wolfssl-lib $(PSA_DES3_STACK_SCRUB_TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(PSA_DES3_STACK_SCRUB_TEST_OBJS) $(LDFLAGS) $(LDLIBS) $(RPATH_WOLFPSA) $(RPATH_WOLFSSL)

psa_ecc_bit_inference_test: require-wolfssl-lib $(PSA_ECC_BIT_INFERENCE_TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(PSA_ECC_BIT_INFERENCE_TEST_OBJS) $(LDFLAGS) $(LDLIBS) $(RPATH_WOLFPSA) $(RPATH_WOLFSSL)

psa_ecc_curve_id_test: require-wolfssl-lib $(PSA_ECC_CURVE_ID_TEST_OBJS) $(PSA_ECC_CURVE_ID_TEST_DEPS)
	$(CC) $(CFLAGS) -o $@ $(PSA_ECC_CURVE_ID_TEST_OBJS) $(PSA_ECC_CURVE_ID_TEST_DEPS) $(LDFLAGS) $(LDLIBS) $(RPATH_WOLFPSA) $(RPATH_WOLFSSL)

psa_random_size_test: require-wolfssl-lib $(PSA_RANDOM_SIZE_TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(PSA_RANDOM_SIZE_TEST_OBJS) $(LDFLAGS) $(LDLIBS) $(RPATH_WOLFPSA) $(RPATH_WOLFSSL)

psa_rsa_pss_interop_test: require-wolfssl-lib $(PSA_RSA_PSS_TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(PSA_RSA_PSS_TEST_OBJS) $(LDFLAGS) $(LDLIBS) $(RPATH_WOLFPSA) $(RPATH_WOLFSSL)

$(PSA_14_TESTS): %: require-wolfssl-lib psa_server/%.o
	$(CC) $(CFLAGS) -o $@ psa_server/$@.o $(LDFLAGS) $(LDLIBS) $(RPATH_WOLFPSA) $(RPATH_WOLFSSL)

# Target-specific: only the curve tests compile with the library's
# user_settings.h (see the comment at USER_SETTINGS_PATH above). The
# value reaches the psa_server/%.o prerequisite's recipe, which is what
# needs the flag and the include path.
psa_ecc_verify_curve_test psa_ecc_ecdh_curve_test psa_ecc_curve_caps_test: \
	CPPFLAGS += $(WOLFSSL_CPPFLAGS) -I$(USER_SETTINGS_PATH)

$(PSA_REGRESSION_TESTS): %: require-wolfssl-lib psa_server/%.o
	$(CC) $(CFLAGS) -o $@ psa_server/$@.o $(LDFLAGS) $(LDLIBS) $(RPATH_WOLFPSA) $(RPATH_WOLFSSL)

ifdef WOLFSSL_HAS_PSA_TLS
psa_tls_server: psa_server/psa_tls_server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS) $(RPATH_WOLFPSA) $(RPATH_WOLFSSL)
endif

psa_tls_client:
	make -C psa_server/tls_client
	cp psa_server/tls_client/psa_tls_client ./psa_tls_client

# devId crypto-callback coverage. wolfCrypt compiles its callback dispatch out
# unless WOLF_CRYPTO_CB is defined, and this test reads wolfCrypt structures
# directly, so it links against a dedicated library built from the repository
# user_settings.h with that knob enabled instead of the shared libwolfpsa.
CRYPTOCB_BUILD_DIR := $(abspath .)/build-cryptocb$(if $(SANITIZE_FLAGS),-asan)
CRYPTOCB_LIB := $(CRYPTOCB_BUILD_DIR)/libwolfpsa-cryptocb.a
CRYPTOCB_CPPFLAGS := -DWOLFSSL_USER_SETTINGS -DWOLF_CRYPTO_CB \
	-I$(abspath $(WOLFSSL_PATH)) -I$(WOLFPSA_ABS) -I$(WOLFPSA_ABS)/wolfpsa \
	-I$(WOLFPSA_ABS)/src

# FORCE, because only the sub-make knows whether a library source changed.
# Without it make treats the existing archive as permanently up to date and
# the test relinks against a stale copy of the code it is meant to guard.
$(CRYPTOCB_LIB): FORCE
	$(MAKE) -C $(WOLFPSA_PATH) $@ \
		LIBNAME=$@ \
		BUILD_DIR=$(CRYPTOCB_BUILD_DIR) \
		WOLFSSL_PATH=$(abspath $(WOLFSSL_PATH)) \
		WOLFSSL_CPPFLAGS="-DWOLFSSL_USER_SETTINGS -DWOLF_CRYPTO_CB" \
		CFLAGS="$(CFLAGS)" \
		LDFLAGS="$(SANITIZE_FLAGS)"

FORCE:

# FORCE here too: the archive is scoped per sanitizer setting but this binary
# is not, so without it an ASAN build left behind stays "up to date".
psa_devid_cryptocb_test: psa_server/psa_devid_cryptocb_test.c $(CRYPTOCB_LIB) FORCE
	$(CC) $(CRYPTOCB_CPPFLAGS) $(CFLAGS) -o $@ $< $(CRYPTOCB_LIB) \
		$(SANITIZE_FLAGS) -lpthread -lm

# Mid-stream KDF failure driven through a crypto callback, so it needs the
# same WOLF_CRYPTO_CB library build as the devId test above.
psa_kdf_zeroize_output_test: psa_server/psa_kdf_zeroize_output_test.c $(CRYPTOCB_LIB) FORCE
	$(CC) $(CRYPTOCB_CPPFLAGS) $(CFLAGS) -o $@ $< $(CRYPTOCB_LIB) \
		$(SANITIZE_FLAGS) -lpthread -lm

# psa_import_key_probe_test ships its own wolfPSA_Store_* backend: the POSIX
# store cannot fail a read probe with an I/O error, only succeed or report
# "not available", so the probe-failure path needs a mock. It therefore links
# against a copy of the static library with the store backend objects removed,
# leaving the test as the only provider of those symbols.
PROBE_BUILD_DIR := $(abspath .)/build-probe$(if $(SANITIZE_FLAGS),-asan)
PROBE_LIB := $(PROBE_BUILD_DIR)/libwolfpsa-nostore.a

# FORCE: only the library build knows whether libwolfpsa.a changed, and a
# stale copy here would test code the library no longer contains.
$(PROBE_LIB): FORCE
	@mkdir -p $(PROBE_BUILD_DIR)
	@test -f $(WOLFPSA_PATH)/libwolfpsa.a || { \
		echo "libwolfpsa.a not found: build the library first (make -C $(WOLFPSA_PATH))"; \
		exit 1; \
	}
	cp $(WOLFPSA_PATH)/libwolfpsa.a $@
	$(AR) d $@ psa_store_posix.o psa_store_zephyr.o

psa_import_key_probe_test: require-wolfssl-lib psa_server/psa_import_key_probe_test.o $(PROBE_LIB)
	$(CC) $(CFLAGS) -o $@ psa_server/psa_import_key_probe_test.o $(PROBE_LIB) \
		$(LDFLAGS) -lwolfssl -lpthread -lm $(RPATH_WOLFSSL)

# Links the static library: it calls the internal wolfPSA_Store_* backend
# API, which the shared library does not export.
BINARIES += psa_store_commit_test

# FORCE, like PROBE_LIB and CRYPTOCB_LIB: only the library build knows whether
# libwolfpsa.a changed, and a stale archive would test store code the library
# no longer contains.
psa_store_commit_test: require-wolfssl-lib psa_server/psa_store_commit_test.o FORCE
	@test -f $(WOLFPSA_PATH)/libwolfpsa.a || { \
		echo "libwolfpsa.a not found: build the library first (make -C $(WOLFPSA_PATH))"; \
		exit 1; \
	}
	$(CC) $(CFLAGS) -o $@ psa_server/psa_store_commit_test.o \
		$(WOLFPSA_PATH)/libwolfpsa.a $(LDFLAGS) -lwolfssl -lpthread -lm $(RPATH_WOLFSSL)

wolfcrypt-psa-benchmark:
	make -C wolfcrypt-benchmark
	cp wolfcrypt-benchmark/wolfcrypt-psa-benchmark ./wolfcrypt-psa-benchmark

require-wolfssl-lib:
ifndef WOLFSSL_LOCAL_LIB
	@echo "No local wolfSSL library found under $(WOLFSSL_PATH) (checked: $(WOLFSSL_CANDIDATE_DIRS)). Build wolfSSL first, for example: make rebuild-wolfssl-psa"
	@exit 1
endif

rebuild-wolfssl-psa: $(WOLFPSA_PATH)/libwolfpsa.so
	@test -d "$(WOLFSSL_PATH)" || { \
		echo "wolfSSL source tree not found at $(WOLFSSL_PATH)"; \
		exit 1; \
	}
	@test -x "$(WOLFSSL_PATH)/configure" || { \
		cd "$(WOLFSSL_PATH)" && ./autogen.sh; \
	}
	cd "$(WOLFSSL_PATH)" && ./configure \
		--enable-psa \
		--enable-pkcallbacks \
		--with-psa-include="$(WOLFPSA_ABS)/wolfpsa" \
		--with-psa-lib="$(WOLFPSA_ABS)" \
		--with-psa-lib-name=wolfpsa \
		CFLAGS="-O2 $(DEBUG_FLAGS) $(SANITIZE_FLAGS)" \
		CPPFLAGS="-DWOLFSSL_PSA_NO_RNG -DWOLFSSL_PSA_NO_HASH -DWOLFSSL_PSA_NO_AES" \
		LDFLAGS="$(SANITIZE_FLAGS) -Wl,-rpath,$(WOLFPSA_ABS) -Wl,-rpath-link,$(WOLFPSA_ABS)"
	$(MAKE) -C "$(WOLFSSL_PATH)" CFLAGS="-O2 $(DEBUG_FLAGS) $(SANITIZE_FLAGS)" LDFLAGS="$(SANITIZE_FLAGS) -Wl,-rpath,$(WOLFPSA_ABS) -Wl,-rpath-link,$(WOLFPSA_ABS)" src/libwolfssl.la

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	make -C psa_server/tls_client clean
	make -C wolfcrypt-benchmark clean
	rm -f psa_server/*.o
	rm -rf $(abspath .)/build-cryptocb $(abspath .)/build-cryptocb-asan
	rm -rf $(abspath .)/build-probe $(abspath .)/build-probe-asan
	rm -f $(BINARIES) psa_devid_cryptocb_test psa_kdf_zeroize_output_test *.o *.log
	rm -f psa_server/*.gcda psa_server/*.gcno
