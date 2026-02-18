SHELL := /bin/bash
EMSDK_DIR := $(CURDIR)/emsdk
EMCC := $(EMSDK_DIR)/upstream/emscripten/emcc

$(EMCC):
	git clone https://github.com/emscripten-core/emsdk.git $(EMSDK_DIR)
	cd $(EMSDK_DIR) && ./emsdk install latest && ./emsdk activate latest

go:
	rm -f go.mod
	mkdir -p build
	cd build && rm -f *.o *.a
	cd nistfalcon && rm -rf build && mkdir build
	cd nistfalcon/src && \
		gcc -c -O3 -fPIC -DALGNAME=falcon512int *.c && \
		ar rcs libfalcon.a *.o && \
		mv *.o ../build && mv *.a ../build
	go mod init github.com/ZKNoxHQ/ETHFALCON/falcon && \
		go mod tidy && \
		echo "remember to type <go get github.com/ZKNoxHQ/ETHFALCON/falcon@latest> in go-ethereum after modification of the go.mod"

js: $(EMCC)
	mkdir -p build
	cd build && rm -f *.o *.a
	cd nistfalcon/src && \
	$(EMCC) \
	  codec.c common.c epervier16.c fft.c fpr.c keygen.c katrng.c nist16.c rng.c shake.c sign.c vrfy.c \
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
	rm -rf build nistfalcon/build falcon.js falcon.wasm go.mod go.sum

.PHONY: go js clean