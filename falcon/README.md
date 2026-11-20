# Bindings Go and javascript

This repository provides binding in Go and javascript of the NIST source files.


## Javascript bindings

### Install Emscripten (emsdk)
Emscripten is a complete compiler toolchain to WebAssembly, using LLVM. It is required to execute the make ```js target```.

 ```bash
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install 5.0.1   # pinned: must match EMSDK_VERSION in falcon/makefile
./emsdk activate 5.0.1
source ./emsdk_env.sh
 ```


### Compile and test

 ```bash
 make js
 node test_falcon.js
 ```
An example of use (key generation, sign and verify) is provided in test_example.js

### Pure JS alternative (noble)

[`noble/`](./noble) provides a signer built on `@noble/post-quantum` with no WASM. It gives the same
keys, signatures and encodings as `falcon.js`. One restriction applies: seeded keygen needs a
**48-byte** seed, while `zknox_crypto_sign_keypair_from_seed` accepts 32 bytes or more. See
[`noble/README.md`](./noble/README.md).

## Go bindings

 ```bash
 make go
go run falcon.go
 ```