# FALCON AND EPERVIER

## Description
This directory is based on the FALCON reference implementation submitted to NIST. We follow the implementation of the public-key recovery that was located in `Extra/` directory. We obtain two new versions of FALCON:
* One version follows the NIST with a 16-bit encoding of the public key and the signature. In FALCON, a specific encoding is used from the fact that integers are always less than $q$ and fit in 14 bits. We decide here to encode with 16 bits, as it fits better with the architecture in Solidity, where a "machine word" is 256-bit long.
    This is done in `src/nist16.c`.
* One version is a public-key recovery version where `pk` is moved to the NTT domain. The public key is finally $H(NTT(h(x)))$ where $h(x)$ is the public key in falcon, and $H$ is a 256-bit output hash function such as Keccak. Note that we did not implement the final hash $H$ here. Thus, the verifier recomputes completely $NTT(h(x))$ and a final check would be required in practice (in solidity).
    This is done in `src/epervier16.c`.
  
## How to use 
We provide a way to create _KAT vectors_ following NIST standards. The generation files are `KAT/PQCgenKAT_sign_zknox.c` and `KAT/PQCgenKAT_sign_epervier_zknox.c`.
First, run:
```bash
make
```
* In order to create the KAT vectors for the NIST (from the initial repository):
    ```bash
    ./build/kat512int
    ```
    This creates a two files `PQCsignKAT_falcon512int.req` and `PQCsignKAT_falcon512int.rsp`. The latter file can be used [here](../../../test/ZKNOX_falconKATS.t.sol) in order to test the solidity verification algorithm, but this requires a `decompression_KAT()` first.
* In order to create the same KAT vectors but with the 16-bit encoding for the public key and the signature:
    ```bash
    ./build/kat512int_zknox
    ```
    Similarly, the vectors of `PQCsignKAT_falcon512int_zknox.rsp` can be manipulated in solidity (see [this same file](../../../test/ZKNOX_falconKATS.t.sol) below).
* In order to create KAT vectors for EPERVIER, the public-key recovery version of FALCON (with 16-bit encoding):
    ```bash
    ./build/kat512int_epervier_zknox
    ```
    It is possible to recover a public key in solidity using EPERVIER from the vectors of the file `PQCsignKAT_falcon512int_epervier_zknox.rsp`, as shown in [this file](../../../test/ZKNOX_epervierKATS.t.sol).

## Randomness
`randombytes()` has two implementations, and a build links exactly one of them:
* `src/randombytes_os.c` uses the operating system CSPRNG (`getentropy()` under Emscripten, which maps to `crypto.getRandomValues`; `getrandom()` on Linux; `getentropy()` on macOS/BSD). It is used by `falcon.js`, `libfalcon.a` (see `../makefile`) and the regression tests. On failure it returns an error and keygen/sign return `-1`; there is no fallback.
* `src/katrng.c` is the deterministic NIST KAT DRBG. Only the KAT generators (`build/kat512int*`) link it, and they seed it with `randombytes_init()` so that the vectors are reproducible. Never link it into code that produces real keys or signatures.

## Tests
```bash
make test   # regression tests (tests/test_zknox.c), SHAKE and Keccak variants
make check  # make test, then regenerate all KAT files and compare the NIST and ETH ones with ../../test/*.rsp
```

## Solidity binding
The commands above should create the following files:
```bash
PQCsignKAT_falcon512int.req
PQCsignKAT_falcon512int.rsp
PQCsignKAT_falcon512int_zknox.req
PQCsignKAT_falcon512int_zknox.rsp
PQCsignKAT_falcon512int_epervier_zknox.req
PQCsignKAT_falcon512int_epervier_zknox.rsp
```
The test vectors can be used in Solidity as explained above. Some tests are provided in [ZKNOX_falconKATS.t.sol](../../../test/ZKNOX_falconKATS.t.sol) and [ZKNOX_epervierKATS.t.sol](../../../test/ZKNOX_falconKATS.t.sol) using the first test vector of the `.rsp` files.