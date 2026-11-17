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

## Go bindings

 ```bash
 make go
go run falcon.go
 ```