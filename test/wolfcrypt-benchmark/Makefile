# wolfPSA wolfCrypt benchmark (PSA + dlopen)

WOLFPSA_PATH ?= ../..
WOLFSSL_PATH ?= $(WOLFPSA_PATH)/../wolfssl
BUILD_DIR ?= build
WOLFPSA_BUILD_DIR := $(WOLFPSA_PATH)/$(BUILD_DIR)
ifneq ($(filter /%,$(BUILD_DIR)),)
WOLFPSA_BUILD_DIR := $(BUILD_DIR)
endif

# libwolfpsa.so location and link flags.
WOLFPSA_LIBDIR ?= $(WOLFPSA_PATH)
WOLFPSA_LIB ?= -lwolfpsa

CC ?= cc

WOLFPSA_DEVID ?= 0x505341

CFLAGS ?= -O2
CPPFLAGS += -I$(WOLFSSL_PATH) -I$(WOLFSSL_PATH)/wolfssl
CPPFLAGS += -I$(WOLFPSA_PATH)/wolfpsa -I$(WOLFPSA_BUILD_DIR)/include
CPPFLAGS += -DWOLFSSL_USER_SETTINGS -U HAVE_CONFIG_H
CPPFLAGS += -DWOLFSSL_HAVE_PSA
CPPFLAGS += -DWOLFPSA_DEVID=$(WOLFPSA_DEVID)
CPPFLAGS += -DWC_USE_DEVID=WOLFPSA_DEVID
CPPFLAGS += -DNO_MAIN_FUNCTION
CPPFLAGS += -I.


# Hide symbols to avoid interposition between wolfSSL and wolfPSA wolfCrypt.
CFLAGS += -fvisibility=hidden

WARNFLAGS ?= -Wall -Wextra
CFLAGS += $(WARNFLAGS)

SANITIZE_FLAGS :=
ifeq ($(ASAN),1)
SANITIZE_FLAGS = -fsanitize=address
endif
CFLAGS += $(SANITIZE_FLAGS)
LDFLAGS += $(SANITIZE_FLAGS)

LDFLAGS += -Wl,--exclude-libs,ALL -Wl,-rpath,'$$ORIGIN/../..' -L$(WOLFPSA_LIBDIR)
LDLIBS += -ldl -lpthread -lm

BIN := wolfcrypt-psa-benchmark
WOLFCRYPT_SRC_ALL := $(wildcard $(WOLFSSL_PATH)/wolfcrypt/src/*.c)
WOLFCRYPT_SRC := $(filter-out \
	$(WOLFSSL_PATH)/wolfcrypt/src/evp.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/misc.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/pkcs7.c \
	$(WOLFSSL_PATH)/wolfcrypt/src/pkcs12.c \
,$(WOLFCRYPT_SRC_ALL))
WOLFCRYPT_PSA_SRC := $(filter-out \
	$(WOLFSSL_PATH)/wolfcrypt/src/port/psa/psa_pkcbs.c \
,$(wildcard $(WOLFSSL_PATH)/wolfcrypt/src/port/psa/*.c))

OBJDIR := build/obj
OBJ := $(patsubst $(WOLFSSL_PATH)/wolfcrypt/src/%.c,$(OBJDIR)/wolfcrypt_%.o,$(WOLFCRYPT_SRC)) \
	$(patsubst $(WOLFSSL_PATH)/wolfcrypt/src/port/psa/%.c,$(OBJDIR)/wolfcrypt_psa_%.o,$(WOLFCRYPT_PSA_SRC)) \
	$(OBJDIR)/benchmark.o \
	$(OBJDIR)/main.o

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(WOLFPSA_LIB) $(LDLIBS)

$(OBJDIR)/wolfcrypt_%.o: $(WOLFSSL_PATH)/wolfcrypt/src/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJDIR)/wolfcrypt_psa_%.o: $(WOLFSSL_PATH)/wolfcrypt/src/port/psa/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJDIR)/benchmark.o: $(WOLFSSL_PATH)/wolfcrypt/benchmark/benchmark.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJDIR)/main.o: main.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(BIN)
