# Build and run the Mbed TLS compatibility tests. Run by
# make MBEDTLS_COMPAT=1 mbedtls-compat-test in the wolfPSA root, which sets
# the paths, all absolute.

ifndef WOLFPSA_PATH
$(error Run make MBEDTLS_COMPAT=1 mbedtls-compat-test in the wolfPSA root)
endif

CFLAGS ?= -O2
# Sources from other repositories build without -Werror
WARNFLAGS ?= -Wall

# Clients use the layer in libwolfpsa.a. WOLFPSA_LDFLAGS has what its build
# needs at link, such as -fsanitize=address with ASAN=1.
WOLFPSA_LIB := $(WOLFPSA_PATH)/libwolfpsa.a
LAYER_FLAGS := -I$(WOLFPSA_PATH)/wolfpsa
LAYER_LIBS := $(WOLFPSA_LIB) -lm $(WOLFPSA_LDFLAGS)

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
# Certificate and key parsing, on Mbed TLS's test data
X509_TEST := $(BUILD_DIR)/x509_crt_test
PK_TEST := $(BUILD_DIR)/pk_test
# Return codes and verify results, client and server in one process
SSL_TEST := $(BUILD_DIR)/ssl_test
# Mbed TLS sample programs, built unchanged from MBEDTLS_PATH
PROGRAMS := $(addprefix $(BUILD_DIR)/programs/ssl/,mini_client ssl_client1 \
	ssl_server ssl_fork_server)
# Threads, with MBEDTLS_THREADING_C=1
ifeq ($(MBEDTLS_THREADING_C),1)
LAYER_FLAGS += -DMBEDTLS_THREADING_C
LAYER_LIBS += -pthread
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
link = $(CC) $(1) $(CPPFLAGS) $(CFLAGS) $(WARNFLAGS) -o $@ \
	$(filter %.c %.o,$^) $(LDFLAGS) $(2)

# Used by programs.sh
export BUILD_DIR WOLFSSL_PATH WOLFSSL_SERVER WOLFSSL_CLIENT MBEDTLS_PATH \
	MBEDTLS_THREADING_C

.PHONY: check wolfssl-check FORCE

check: $(CLIENT) $(X509_TEST) $(PK_TEST) $(SSL_TEST) $(PROGRAMS) \
		$(WOLFSSL_SERVER) $(WOLFSSL_CLIENT)
	./programs.sh

$(CLIENT): client-tls-mbedtls.c
$(X509_TEST): x509_crt_test.c
$(PK_TEST): pk_test.c
$(SSL_TEST): ssl_test.c
$(PROGRAMS): $(BUILD_DIR)/programs/%: $(MBEDTLS_PATH)/programs/%.c
$(PROGRAMS): override CPPFLAGS += -I$(MBEDTLS_PATH)/tests/include
$(addprefix $(BUILD_DIR)/programs/ssl/,ssl_client1 ssl_server \
	ssl_fork_server ssl_pthread_server): $(CERTS)
$(CLIENT) $(X509_TEST) $(PK_TEST) $(SSL_TEST) $(PROGRAMS): \
		$(WOLFPSA_LIB)
	@mkdir -p $(@D)
	$(call link,$(LAYER_FLAGS),$(LAYER_LIBS))

$(CERTS_H):
	@mkdir -p $(@D)
	PYTHONPATH=$(MBEDTLS_PATH)/framework/scripts python3 \
		$(MBEDTLS_PATH)/framework/scripts/generate_test_cert_macros.py \
		--output $@

$(CERTS): $(MBEDTLS_PATH)/tests/src/certs.c $(CERTS_H)
	$(CC) $(MBEDTLS_FLAGS) $(CPPFLAGS) $(CFLAGS) $(WARNFLAGS) -c -o $@ $<

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
