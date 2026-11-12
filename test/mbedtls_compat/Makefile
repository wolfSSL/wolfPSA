# Build and run the Mbed TLS compatibility tests. Run by
# make MBEDTLS_COMPAT=1 mbedtls-compat-test in the wolfPSA root, which sets
# the paths, all absolute.

ifndef WOLFPSA_PATH
$(error Run make MBEDTLS_COMPAT=1 mbedtls-compat-test in the wolfPSA root)
endif

CFLAGS ?= -O2
WARNFLAGS ?= -Wall

# Tests use the layer in libwolfpsa.a. WOLFPSA_LDFLAGS has what its build
# needs at link, such as -fsanitize=address with ASAN=1. PSA_CONFIG_DIR has
# the generated PSA_WANT_* header.
WOLFPSA_LIB := $(WOLFPSA_PATH)/libwolfpsa.a
LAYER_FLAGS := -I$(WOLFPSA_PATH)/wolfpsa -I$(PSA_CONFIG_DIR)
LAYER_LIBS := $(WOLFPSA_LIB) -lm $(WOLFPSA_LDFLAGS)
ifeq ($(MBEDTLS_THREADING_C),1)
LAYER_FLAGS += -DMBEDTLS_THREADING_C
LAYER_LIBS += -pthread
endif

# Certificate and key parsing, on Mbed TLS's test data
DATA := $(MBEDTLS_PATH)/framework/data_files
TESTS := $(addprefix $(BUILD_DIR)/,x509_crt_test pk_test)

# x509_crt_test sets wolfSSL's allocators. WOLFSSL_FLAGS configures the
# wolfSSL headers as for libwolfpsa.a.
$(BUILD_DIR)/x509_crt_test: LAYER_FLAGS += $(WOLFSSL_FLAGS) -I$(WOLFPSA_PATH)

.PHONY: check

check: $(TESTS)
	@if [ ! -f $(DATA)/server5.crt ]; then \
		echo "$(DATA) not found, run git submodule update --init" \
			"in $(MBEDTLS_PATH)"; \
		exit 1; \
	fi
	@fails=0; for t in $(TESTS); do \
		(cd $(DATA) && $(WRAP) $$t) || fails=$$((fails + 1)); \
	done; \
	[ $$fails -eq 0 ]

$(BUILD_DIR)/%: %.c $(WOLFPSA_LIB)
	@mkdir -p $(@D)
	$(CC) $(LAYER_FLAGS) $(CPPFLAGS) $(CFLAGS) $(WARNFLAGS) -o $@ $< \
		$(LDFLAGS) $(LAYER_LIBS)
