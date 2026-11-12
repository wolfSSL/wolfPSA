# Build and run the Mbed TLS compatibility tests. Run by the mbedtls-compat-*
# targets in the wolfPSA root (make help there), which set the paths, all
# absolute.

ifndef WOLFPSA_PATH
$(error Run make MBEDTLS_COMPAT=1 mbedtls-compat-test in the wolfPSA root)
endif

CFLAGS ?= -O2
# Sources from other repositories build without -Werror
WARNFLAGS ?= -Wall

# Tests use the layer in libwolfpsa.a. WOLFPSA_LDFLAGS has what its build
# needs at link, such as -fsanitize=address with ASAN=1, and SANITIZE_FLAGS
# what the tests need to compile with it. PSA_CONFIG_DIR has the generated
# PSA_WANT_* header.
WOLFPSA_LIB := $(WOLFPSA_PATH)/libwolfpsa.a
LAYER_FLAGS := -I$(WOLFPSA_PATH)/wolfpsa \
	-I$(WOLFPSA_PATH)/wolfpsa/mbedtls_compat -I$(PSA_CONFIG_DIR)
LAYER_LIBS := $(WOLFPSA_LIB) -lm $(WOLFPSA_LDFLAGS)
ifeq ($(MBEDTLS_THREADING_C),1)
LAYER_FLAGS += -DMBEDTLS_THREADING_C
LAYER_LIBS += -pthread
endif

# Mbed TLS 4.x: MBEDTLS_PATH, or by default a shallow clone of MBEDTLS_REF
MBEDTLS_URL := https://github.com/Mbed-TLS/mbedtls.git
MBEDTLS_REF := ba07f72f934a002021731a2bb5e564e5905f6569
MBEDTLS_CLONE := $(BUILD_DIR)/mbedtls
MBEDTLS_PATH ?= $(MBEDTLS_CLONE)
# Named with the ref, so a new MBEDTLS_REF clones again
MBEDTLS_STAMP := $(MBEDTLS_CLONE)-$(MBEDTLS_REF)

# Mbed TLS's test data
DATA := $(MBEDTLS_PATH)/framework/data_files
# Certificate, key and PEM parsing, and TLS return codes and verify results
# with a client and a server in one process
UNIT := $(addprefix $(BUILD_DIR)/,x509_crt_test pk_test pem_test ssl_test)

# The peers are the wolfSSL example server and client, from a wolfSSL
# configured out of tree from WOLFSSL_PATH, so they do not depend on wolfPSA's
# settings
WOLFSSL_BUILD := $(BUILD_DIR)/wolfssl
# Mbed TLS's test CA test-ca2.crt has NULL ECDSA parameters, which
# ssl_server sends in its chain
WOLFSSL_CONFIG := --enable-static --disable-shared \
	CPPFLAGS=-DWOLFSSL_ECC_SIGALG_PARAMS_NULL_ALLOWED
WOLFSSL_SERVER := $(WOLFSSL_BUILD)/examples/server/server
WOLFSSL_CLIENT := $(WOLFSSL_BUILD)/examples/client/client

# Mbed TLS migration guide client
CLIENT := $(BUILD_DIR)/client-tls-mbedtls
# Mbed TLS sample programs, built unchanged from MBEDTLS_PATH
PROGRAMS := $(addprefix $(BUILD_DIR)/programs/ssl/,mini_client ssl_server \
	ssl_fork_server)
# Threads, with MBEDTLS_THREADING_C=1
ifeq ($(MBEDTLS_THREADING_C),1)
PROGRAMS += $(BUILD_DIR)/programs/ssl/ssl_pthread_server
endif
# Mbed TLS test certificates, data only. certs.c and the generated
# test_certs.h build against the Mbed TLS checkout's own headers.
CERTS := $(BUILD_DIR)/certs.o
CERTS_H := $(BUILD_DIR)/include/test/test_certs.h
MBEDTLS_FLAGS := -I$(BUILD_DIR)/include -I$(MBEDTLS_PATH)/include \
	-I$(MBEDTLS_PATH)/tests/include \
	$(addprefix -I$(MBEDTLS_PATH)/tf-psa-crypto/,include core \
		drivers/builtin/include)

# Mbed TLS's ssl suite: the cases in cases.txt, on the clone and its patch
SUITE := $(CURDIR)/ssl_suite
SUITE_BUILD := $(BUILD_DIR)/ssl_suite
SUITE_PATCHED := $(MBEDTLS_CLONE)-patched
SUITE_NAME := $(SUITE_BUILD)/test_suite_ssl_public
SUITE_HELPERS := $(addprefix $(SUITE_BUILD)/,helpers.o random.o \
	threading_helpers.o test_memory.o)
SUITE_OBJS := $(SUITE_NAME).o $(SUITE_BUILD)/ssl_helpers.o \
	$(SUITE_BUILD)/ssl_helpers_port.o $(SUITE_BUILD)/psa_crypto_helpers.o \
	$(SUITE_HELPERS)
SUITE_TEMPLATES := $(MBEDTLS_CLONE)/tf-psa-crypto/tests/suites
# wolfPSA's headers first; Mbed TLS's public headers are not on the path.
# TEST_WOLFPSA leaves out the helpers' calls that wolfPSA does not have yet.
SUITE_FLAGS := $(LAYER_FLAGS) -DTEST_WOLFPSA -I$(SUITE) -I$(SUITE)/shim \
	$(addprefix -I$(MBEDTLS_CLONE)/,framework/tests/include tests/include \
		tf-psa-crypto/tests/include framework/tests/src) \
	-idirafter $(MBEDTLS_CLONE)/tf-psa-crypto/core
SUITE_PUBLIC_HEADERS := $(MBEDTLS_CLONE)/(tf-psa-crypto/)?include/
# The same suite and ssl_helpers_port.c on Mbed TLS's CMake build of the clone
REF_BUILD := $(BUILD_DIR)/ssl_suite_ref
REF_NAME := $(REF_BUILD)/test_suite_ssl_public

# $(call run_suite,title,check.py options) runs the suite $< from the clone's
# tests/, for the .data's ../framework/data_files paths. check.py compares
# each case with cases.txt, not the suite's exit code.
define run_suite
@rm -f $(dir $<)outcome.csv
cd $(MBEDTLS_CLONE)/tests && \
	MBEDTLS_TEST_OUTCOME_FILE=$(dir $<)outcome.csv $(WRAP) $< \
	$(SUITE_NAME).datax > $<.log 2>&1 || true
@echo "$(1), $(MBEDTLS_REF)"
@python3 $(SUITE)/check.py $(2) $(SUITE)/cases.txt $(dir $<)outcome.csv || \
	{ echo "Log: $<.log"; exit 1; }
endef

# $(call link,flags,libraries) links the C source and objects among the
# prerequisites
link = $(CC) $(1) $(CPPFLAGS) $(CFLAGS) $(SANITIZE_FLAGS) $(WARNFLAGS) \
	-o $@ $(filter %.c %.o,$^) $(LDFLAGS) $(2)

# Used by programs.sh
export BUILD_DIR WOLFSSL_PATH WOLFSSL_SERVER WOLFSSL_CLIENT MBEDTLS_PATH \
	MBEDTLS_THREADING_C
# With ASAN=1: let a preloaded library, such as faketime's, come first
ASAN_LINK_ORDER := verify_asan_link_order=0
export ASAN_OPTIONS := $(if $(ASAN_OPTIONS),$(ASAN_OPTIONS):)$(ASAN_LINK_ORDER)
# select.py and check.py import cases.py: no __pycache__ in the source tree
export PYTHONDONTWRITEBYTECODE := 1

.PHONY: test unit programs suite suite-ref suite-patch data-check \
	wolfssl-check FORCE

# Everything that tests wolfPSA
test: unit programs suite

unit: $(UNIT) | data-check
	@fails=0; for t in $(UNIT); do \
		(cd $(DATA) && $(WRAP) $$t) || fails=$$((fails + 1)); \
	done; \
	[ $$fails -eq 0 ] || { echo "$$fails of $(words $(UNIT)) failed"; exit 1; }

programs: $(CLIENT) $(PROGRAMS) $(WOLFSSL_SERVER) $(WOLFSSL_CLIENT) | \
		data-check
	./programs.sh

suite: $(SUITE_NAME)
	$(call run_suite,Mbed TLS ssl suite)

# Run our modified suite on Mbed TLS's own libraries. Every case must pass,
# which shows the ported helpers still test what upstream's do.
suite-ref: $(REF_NAME)
	$(call run_suite,Mbed TLS ssl suite on Mbed TLS,--all-pass)

# Saves the clone's changes to mbedtls.patch, below its license lines
suite-patch:
	@mkdir -p $(SUITE_BUILD)
	{ sed '/^diff --git/,$$d' $(SUITE)/mbedtls.patch; \
		git -C $(MBEDTLS_CLONE) -c diff.suppressBlankEmpty=true \
		diff --no-ext-diff HEAD; } > $(SUITE_BUILD)/mbedtls.patch
	mv $(SUITE_BUILD)/mbedtls.patch $(SUITE)/mbedtls.patch
	touch $(SUITE_PATCHED)

data-check:
	@if [ ! -f $(DATA)/server5.crt ]; then \
		echo "$(DATA) not found, run git submodule update --init" \
			"in $(MBEDTLS_PATH)"; \
		exit 1; \
	fi

# x509_crt_test sets wolfSSL's allocators. WOLFSSL_FLAGS configures the
# wolfSSL headers as for libwolfpsa.a.
$(BUILD_DIR)/x509_crt_test: LAYER_FLAGS += $(WOLFSSL_FLAGS) -I$(WOLFPSA_PATH)

$(CLIENT): client-tls-mbedtls.c
$(UNIT): $(BUILD_DIR)/%: %.c
$(PROGRAMS): $(BUILD_DIR)/programs/%: $(MBEDTLS_PATH)/programs/%.c
$(PROGRAMS): override CPPFLAGS += -I$(MBEDTLS_PATH)/tests/include
$(addprefix $(BUILD_DIR)/programs/ssl/,ssl_server ssl_fork_server \
	ssl_pthread_server): $(CERTS)
$(CLIENT) $(UNIT) $(PROGRAMS): $(WOLFPSA_LIB)
	@mkdir -p $(@D)
	$(call link,$(LAYER_FLAGS),$(LAYER_LIBS))

$(CERTS_H):
	@mkdir -p $(@D)
	PYTHONPATH=$(MBEDTLS_PATH)/framework/scripts python3 \
		$(MBEDTLS_PATH)/framework/scripts/generate_test_cert_macros.py \
		--output $@

$(CERTS): $(MBEDTLS_PATH)/tests/src/certs.c $(CERTS_H)
	$(CC) $(MBEDTLS_FLAGS) $(CPPFLAGS) $(CFLAGS) $(SANITIZE_FLAGS) \
		$(WARNFLAGS) -c -o $@ $<

$(MBEDTLS_STAMP):
	rm -rf $(MBEDTLS_CLONE) $(MBEDTLS_CLONE)-*
	git init -q $(MBEDTLS_CLONE)
	git -C $(MBEDTLS_CLONE) fetch -q --depth 1 $(MBEDTLS_URL) $(MBEDTLS_REF)
	git -C $(MBEDTLS_CLONE) checkout -q FETCH_HEAD
	git -C $(MBEDTLS_CLONE) submodule update -q --init --depth 1
	touch $@

ifeq ($(MBEDTLS_PATH),$(MBEDTLS_CLONE))
$(PROGRAMS) $(CERTS) $(CERTS_H): $(MBEDTLS_STAMP)
data-check: | $(MBEDTLS_STAMP)
endif
# Files from the clone exist once it is made
.PRECIOUS: $(MBEDTLS_CLONE)/%
$(MBEDTLS_CLONE)/%: | $(MBEDTLS_STAMP) ;

# A newer patch resets the clone, dropping edits made there
$(SUITE_PATCHED): $(SUITE)/mbedtls.patch $(MBEDTLS_STAMP)
	git -C $(MBEDTLS_CLONE) reset -q --hard
	git -C $(MBEDTLS_CLONE) apply $<
	touch $@

# One recipe writes the .c and the .datax
$(SUITE_NAME).datax: $(SUITE_NAME).c ;
$(SUITE_NAME).c: $(SUITE)/select.py $(SUITE)/cases.py $(SUITE)/cases.txt \
		$(SUITE_PATCHED)
	@mkdir -p $(@D)
	python3 $< $(SUITE)/cases.txt $(MBEDTLS_CLONE)/tests/suites $(@D)
	python3 $(MBEDTLS_CLONE)/framework/scripts/generate_test_code.py \
		-f $(SUITE_NAME).function -d $(SUITE_NAME).data \
		-t $(SUITE_TEMPLATES)/main_test.function \
		-p $(SUITE_TEMPLATES)/host_test.function -s $(SUITE_TEMPLATES) \
		--helpers-file $(SUITE_TEMPLATES)/helpers.function -o $(@D)

$(SUITE_HELPERS): $(SUITE_BUILD)/%.o: $(MBEDTLS_CLONE)/framework/tests/src/%.c
$(SUITE_BUILD)/ssl_helpers.o: \
	$(MBEDTLS_CLONE)/tests/src/test_helpers/ssl_helpers.c
$(SUITE_BUILD)/ssl_helpers_port.o: $(SUITE)/ssl_helpers_port.c
$(SUITE_BUILD)/psa_crypto_helpers.o: $(SUITE)/shim/psa_crypto_helpers.c
$(SUITE_NAME).o: $(SUITE_NAME).c
# The header's static functions include some for cases left out
$(SUITE_NAME).o: WARNFLAGS += -Wno-unused-function
$(SUITE_OBJS): $(SUITE_PATCHED)
	@mkdir -p $(@D)
	$(CC) $(SUITE_FLAGS) $(CPPFLAGS) $(CFLAGS) $(SANITIZE_FLAGS) \
		$(WARNFLAGS) -MD -MP -c -o $@ $(filter %.c,$^)
	@if grep -q -E '$(SUITE_PUBLIC_HEADERS)' $(@:.o=.d); then \
		grep -o -E '$(SUITE_PUBLIC_HEADERS)[^ :]*' $(@:.o=.d) | \
			sort -u; \
		echo "$@: uses Mbed TLS's public headers"; rm $@; exit 1; \
	fi

$(SUITE_NAME): $(SUITE_OBJS) $(CERTS) $(WOLFPSA_LIB) $(SUITE_NAME).datax
	$(call link,,$(LAYER_LIBS))

# Mbed TLS's CMake build needs tf-psa-crypto's own framework submodule, and
# Python's jinja2 and jsonschema
$(REF_BUILD)/CMakeCache.txt: $(MBEDTLS_STAMP) | $(SUITE_PATCHED)
	git -C $(MBEDTLS_CLONE) submodule update -q --init --depth 1 --recursive
	cmake -S $(SUITE) -B $(REF_BUILD) -DCMAKE_BUILD_TYPE=Release \
		-DMBEDTLS_DIR=$(MBEDTLS_CLONE) -DSUITE_C=$(SUITE_NAME).c

# CMake tracks the sources
$(REF_NAME): $(REF_BUILD)/CMakeCache.txt $(SUITE_NAME).datax FORCE
	+cmake --build $(REF_BUILD) --target $(@F)

-include $(SUITE_OBJS:.o=.d)

# configure refuses a clone that is configured in place. autogen.sh only adds
# files git ignores.
wolfssl-check:
	@if [ -f $(WOLFSSL_PATH)/config.status ]; then \
		echo "Run make distclean in $(WOLFSSL_PATH)"; exit 1; \
	fi

$(WOLFSSL_PATH)/configure:
	cd $(@D) && ./autogen.sh

# Contains WOLFSSL_PATH. Another path starts the build again.
WOLFSSL_STAMP := $(WOLFSSL_BUILD).path
$(WOLFSSL_STAMP): FORCE
	@mkdir -p $(@D)
	@if [ "$$(cat $@ 2>/dev/null)" != "$(WOLFSSL_PATH)" ]; then \
		rm -rf $(WOLFSSL_BUILD); echo "$(WOLFSSL_PATH)" > $@; \
	fi

$(WOLFSSL_BUILD)/Makefile: Makefile $(WOLFSSL_STAMP) \
		$(WOLFSSL_PATH)/configure | wolfssl-check
	@mkdir -p $(@D)
	cd $(@D) && $(WOLFSSL_PATH)/configure CC="$(CC)" $(WOLFSSL_CONFIG)

# One make builds both, so the library is not built twice at once
$(WOLFSSL_CLIENT): $(WOLFSSL_SERVER)
$(WOLFSSL_SERVER): $(WOLFSSL_BUILD)/Makefile FORCE
	$(MAKE) -C $(WOLFSSL_BUILD) examples/server/server examples/client/client

FORCE:
