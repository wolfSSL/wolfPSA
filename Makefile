# Simple static build for wolfPSA

WOLFSSL_PATH ?= ../wolfssl
USER_SETTINGS_PATH ?= $(CURDIR)/wolfpsa
PSA_INCLUDE ?=

BUILD_DIR ?= build
OBJDIR := $(BUILD_DIR)/obj
OBJDIR_PIC := $(BUILD_DIR)/obj.pic
LIBNAME := libwolfpsa.a
SHLIBNAME := libwolfpsa.so
EXPORT_MAP := $(CURDIR)/wolfpsa.map

CC ?= cc
AR ?= ar
RANLIB ?= ranlib

SRC := $(wildcard src/*.c)
OBJ := $(patsubst src/%.c,$(OBJDIR)/%.o,$(SRC))
OBJ_PIC := $(patsubst src/%.c,$(OBJDIR_PIC)/%.o,$(SRC))

WOLFCRYPT_SRC := \
	$(WOLFSSL_PATH)/wolfcrypt/src/aes.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/ascon.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/asn.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/chacha.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/chacha20_poly1305.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/cmac.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/coding.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/cpuid.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/cryptocb.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/curve25519.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/curve448.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/des3.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/dsa.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/ecc.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/ecc_fp.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/ed25519.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/ed448.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/error.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/fe_operations.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/ge_operations.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/fe_448.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/ge_448.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/hash.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/hmac.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/integer.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/kdf.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/logging.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/md5.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/memory.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/poly1305.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/pwdbased.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/random.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/ripemd.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/rsa.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/sha.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/sha256.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/sha3.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/sha512.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/signature.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/sp_c32.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/sp_c64.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/sp_int.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/sp_x86_64.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/tfm.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/wc_encrypt.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/wc_lms.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/wc_lms_impl.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/wc_mldsa.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/wc_mlkem.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/wc_mlkem_poly.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/wc_port.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/wc_xmss.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/wc_xmss_impl.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/wolfentropy.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/wolfmath.c

WOLFCRYPT_OBJ := $(patsubst $(WOLFSSL_PATH)/wolfcrypt/src/%.c,$(OBJDIR)/wolfcrypt_%.o,$(WOLFCRYPT_SRC))
WOLFCRYPT_OBJ_PIC := $(patsubst $(WOLFSSL_PATH)/wolfcrypt/src/%.c,$(OBJDIR_PIC)/wolfcrypt_%.o,$(WOLFCRYPT_SRC))

WOLFSSL_CPPFLAGS ?= -DWOLFSSL_USER_SETTINGS

CPPFLAGS += -I$(WOLFSSL_PATH) -I$(USER_SETTINGS_PATH) \
	-I$(CURDIR) -I$(CURDIR)/wolfpsa -I$(CURDIR)/src $(WOLFSSL_CPPFLAGS)
ifneq ($(strip $(PSA_INCLUDE)),)
CPPFLAGS += -I$(PSA_INCLUDE)
endif

DEPFLAGS := -MMD -MP
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
# AES_FAST=1 waives the PSA constant-time AES requirement and takes
# wolfCrypt's faster T-table core instead. See src/psa_config.h.
ifeq ($(AES_FAST),1)
CPPFLAGS += -DWOLFPSA_AES_FAST
endif
CFLAGS += $(DEBUG_FLAGS) $(SANITIZE_FLAGS)
LDFLAGS += $(SANITIZE_FLAGS)

# gcov coverage (make cov): instrument the library and the unit tests, run
# the tests, and emit an HTML report of which lines of src/*.c they cover.
# The unit tests link the instrumented shared library, so the runtime .gcda
# files land next to the PIC objects in build/obj.pic.
COV_DIR := build/coverage
OPEN_CMD := $(shell command -v open >/dev/null 2>&1 && echo open || echo xdg-open)
ifeq ($(COV),1)
CFLAGS += --coverage
LDFLAGS += --coverage
endif

.PHONY: all clean psa-objects unit-run run-tests cov covclean

all: $(LIBNAME) $(SHLIBNAME)

# Compile only wolfPSA's own sources, skipping the wolfCrypt sources pulled
# in from WOLFSSL_PATH. Used by build-config-matrix lanes that exercise a
# configuration where wolfPSA's own exclusions are the point and the
# bundled wolfCrypt sources are out of scope.
psa-objects: $(OBJ)

$(LIBNAME): $(OBJ) $(WOLFCRYPT_OBJ)
	$(AR) rcs $@ $^
	$(RANLIB) $@

$(SHLIBNAME): $(OBJ_PIC) $(WOLFCRYPT_OBJ_PIC) $(EXPORT_MAP)
	$(CC) -shared -Wl,--version-script,$(EXPORT_MAP) -Wl,-Bsymbolic-functions -o $@ $(filter-out $(EXPORT_MAP),$^) $(LDFLAGS)

$(OBJDIR)/%.o: src/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CPPFLAGS) $(DEPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJDIR)/wolfcrypt_%.o: $(WOLFSSL_PATH)/wolfcrypt/src/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CPPFLAGS) $(DEPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJDIR_PIC)/%.o: src/%.c
	@mkdir -p $(OBJDIR_PIC)
	$(CC) $(CPPFLAGS) $(DEPFLAGS) $(CFLAGS) -fPIC -c $< -o $@

$(OBJDIR_PIC)/wolfcrypt_%.o: $(WOLFSSL_PATH)/wolfcrypt/src/%.c
	@mkdir -p $(OBJDIR_PIC)
	$(CC) $(CPPFLAGS) $(DEPFLAGS) $(CFLAGS) -fPIC -c $< -o $@

# The unit tests. The servers (psa_tls_client, psa_tls_server) and the
# benchmark are not unit tests and are not listed.
UNIT_TESTS := psa_api_test \
	psa_crypto_init_test \
	psa_aead_multipart_test \
	psa_copy_key_narrowing_test \
	psa_ecc_bit_inference_test \
	psa_des3_stack_scrub_test \
	psa_ecc_curve_id_test \
	psa_random_size_test \
	psa_rsa_pss_interop_test \
	psa_mldsa_test \
	psa_mlkem_test \
	psa_xof_test \
	psa_key_wrap_test \
	psa_sign_context_test \
	psa_lms_xmss_verify_test \
	psa_ascon_xchacha_test \
	psa_sp800_108_test \
	psa_14_misc_test \
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
	psa_import_key_probe_test \
	psa_store_commit_test \
	psa_store_read_open_test \
	psa_store_dir_validation_test \
	psa_devid_cryptocb_test \
	psa_kdf_zeroize_output_test \
	psa_import_zero_length_test \
	psa_copy_key_cross_lifetime_test \
	psa_zero_capacity_buffer_test

# Run the unit test loop from the repo root (psa_rsa_pss_interop_test reads
# its certificate relative to the root). Assumes the tests are already built.
run-tests:
	@for t in $(UNIT_TESTS); do \
	    echo "=== $$t ==="; \
	    rm -rf .store test/.store; \
	    ./test/$$t || exit 1; \
	done

# Build the library and the unit tests, then run every unit test.
unit-run: all
	@$(MAKE) -C test $(UNIT_TESTS)
	@$(MAKE) run-tests

# Build everything with gcov instrumentation, run the unit tests, and emit an
# HTML coverage report for src/*.c (the bundled wolfCrypt sources are
# excluded by the -f filter). The instrumented objects are dropped once the
# report exists: a later non-coverage build would otherwise reuse them and
# fail to link (undefined __gcov_init). The report itself is kept. A test
# failure is recorded and re-raised at the end rather than aborting the
# recipe, so the drop always happens.
cov:
	@command -v gcovr >/dev/null 2>&1 || { \
	    echo "gcovr not found: install it before running 'make cov'"; \
	    exit 1; \
	}
	@$(MAKE) clean
	@$(MAKE) -C test clean
	@$(MAKE) all COV=1
	@$(MAKE) -C test $(UNIT_TESTS) COV=1
	@rm -f $(BUILD_DIR)/.cov-tests-failed
	@$(MAKE) run-tests || touch $(BUILD_DIR)/.cov-tests-failed
	@mkdir -p $(COV_DIR)
	@echo "[COV] gcovr html"
	@gcovr -r . -f '^src/.*\.c$$' \
	    --gcov-ignore-errors=no_working_dir_found \
	    --html-medium-threshold 60 \
	    --html-high-threshold 80 \
	    --html-details -o $(COV_DIR)/index.html
	@echo "[COV] report: $(COV_DIR)/index.html"
	@echo "[COV] dropping instrumented objects"
	@rm -rf $(OBJDIR) $(OBJDIR_PIC) $(LIBNAME) $(SHLIBNAME)
	@$(MAKE) -C test clean
	@if [ -n "$$DISPLAY" ] || [ -n "$$WAYLAND_DISPLAY" ] || \
	    [ "$$(uname -s)" = "Darwin" ]; then \
	    $(OPEN_CMD) $(COV_DIR)/index.html || true; \
	fi
	@if [ -f $(BUILD_DIR)/.cov-tests-failed ]; then \
	    rm -f $(BUILD_DIR)/.cov-tests-failed; \
	    echo "[COV] unit tests FAILED (report above is still valid)"; \
	    exit 1; \
	fi

# Remove gcov artifacts and the coverage report.
covclean:
	rm -f $(OBJDIR)/*.gcda $(OBJDIR)/*.gcno \
	      $(OBJDIR_PIC)/*.gcda $(OBJDIR_PIC)/*.gcno
	find test \( -name '*.gcda' -o -name '*.gcno' \) -delete
	rm -rf $(COV_DIR)

clean:
	rm -rf $(BUILD_DIR) $(LIBNAME) $(SHLIBNAME)

-include $(OBJ:.o=.d) $(WOLFCRYPT_OBJ:.o=.d)
-include $(OBJ_PIC:.o=.d) $(WOLFCRYPT_OBJ_PIC:.o=.d)
