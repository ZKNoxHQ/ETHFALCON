SHELL := /bin/bash

# Emscripten toolchain, pinned so that falcon.js rebuilds reproducibly.
# Override EMSDK_DIR to use an existing emsdk checkout:
#   make js EMSDK_DIR=/path/to/emsdk
EMSDK_VERSION := 5.0.1
EMSDK_DIR := $(CURDIR)/emsdk
EMCC := $(EMSDK_DIR)/upstream/emscripten/emcc

# C sources linked into falcon.js and libfalcon.a.
# randombytes() comes from randombytes_os.c (OS CSPRNG: getentropy() ->
# crypto.getRandomValues() under Emscripten, getrandom() on Linux).
# katrng.c (the NIST KAT DRBG, deterministic) is for the KAT generators
# in nistfalcon/ only and must never be linked here.
SRC_COMMON := codec.c common.c fft.c fpr.c keygen.c rng.c shake.c sign.c vrfy.c \
	keccak_prng.c keccak256.c randombytes_os.c
SRC_JS := $(SRC_COMMON) nist16.c epervier16.c
SRC_GO := $(SRC_COMMON) nist.c nist16.c epervier16.c

$(EMCC):
	git clone https://github.com/emscripten-core/emsdk.git $(EMSDK_DIR)
	cd $(EMSDK_DIR) && ./emsdk install $(EMSDK_VERSION) && ./emsdk activate $(EMSDK_VERSION)

# Builds nistfalcon/build/libfalcon.a, which falcon.go links. go.mod is
# tracked and left untouched.
go:
	mkdir -p nistfalcon/build
	rm -f nistfalcon/build/libfalcon.a nistfalcon/build/go_*.o
	cd nistfalcon/src && \
		for f in $(SRC_GO); do \
			gcc -c -O3 -fPIC -DALGNAME=falcon512int $$f -o ../build/go_$${f%.c}.o || exit 1; \
		done
	ar rcs nistfalcon/build/libfalcon.a $(addprefix nistfalcon/build/go_,$(SRC_GO:.c=.o))
	rm -f nistfalcon/build/go_*.o
	@echo "remember to type <go get github.com/ZKNoxHQ/ETHFALCON/falcon@latest> in go-ethereum after modification of the library"

js: $(EMCC)
	@$(EMCC) --version | head -n 1 | grep -q " $(EMSDK_VERSION) " || \
		{ echo "error: $(EMCC) is not emscripten $(EMSDK_VERSION)"; \
		  echo "run: cd $(EMSDK_DIR) && ./emsdk install $(EMSDK_VERSION) && ./emsdk activate $(EMSDK_VERSION)"; \
		  exit 1; }
	cd nistfalcon/src && \
	$(EMCC) \
	  $(SRC_JS) \
	  -I. \
	  -s WASM=1 \
	  -s SINGLE_FILE=1 \
	  -s MODULARIZE=1 \
	  -s EXPORT_NAME="Module" \
	  -s EXPORTED_FUNCTIONS='["_zknox_crypto_sign_keypair", "_zknox_crypto_sign_keypair_from_seed", "_zknox_crypto_sign", "_zknox_crypto_sign_open", "_malloc", "_free"]' \
	  -s EXPORTED_RUNTIME_METHODS='["ccall", "cwrap", "HEAPU8", "HEAPU32"]' \
	  -s ALLOW_MEMORY_GROWTH=1 \
	  -O3 \
	  -o ../../falcon.js

clean:
	rm -f nistfalcon/build/go_*.o falcon.js falcon.wasm

.PHONY: go js clean
