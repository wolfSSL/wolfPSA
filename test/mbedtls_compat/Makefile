# Build and run the Mbed TLS compatibility tests. Run by the
# mbedtls-compat-test, mbedtls-compat-unit and mbedtls-compat-programs
# targets in the wolfPSA root, which set the paths, all absolute.

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
PROGRAMS := $(addprefix $(BUILD_DIR)/programs/ssl/,mini_client ssl_client1 \
	ssl_server ssl_fork_server)
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

.PHONY: test unit programs data-check wolfssl-check FORCE

test: unit programs

unit: $(UNIT) | data-check
	@fails=0; for t in $(UNIT); do \
		(cd $(DATA) && $(WRAP) $$t) || fails=$$((fails + 1)); \
	done; \
	[ $$fails -eq 0 ] || { echo "$$fails of $(words $(UNIT)) failed"; exit 1; }

programs: $(CLIENT) $(PROGRAMS) $(WOLFSSL_SERVER) $(WOLFSSL_CLIENT) | \
		data-check
	./programs.sh

data-check:
	@if [ ! -f $(DATA)/server5.crt ]; then \
		echo "$(DATA) not found, run git submodule update --init" \
			"in $(MBEDTLS_PATH)"; \
		exit 1; \
	fi

# x509_crt_test and ssl_test set wolfSSL's allocators. WOLFSSL_FLAGS
# configures the wolfSSL headers as for libwolfpsa.a.
$(addprefix $(BUILD_DIR)/,x509_crt_test ssl_test): \
	LAYER_FLAGS += $(WOLFSSL_FLAGS) -I$(WOLFPSA_PATH)

$(CLIENT): client-tls-mbedtls.c
$(UNIT): $(BUILD_DIR)/%: %.c
$(PROGRAMS): $(BUILD_DIR)/programs/%: $(MBEDTLS_PATH)/programs/%.c
$(PROGRAMS): override CPPFLAGS += -I$(MBEDTLS_PATH)/tests/include
$(addprefix $(BUILD_DIR)/programs/ssl/,ssl_client1 ssl_server \
	ssl_fork_server ssl_pthread_server): $(CERTS)
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
