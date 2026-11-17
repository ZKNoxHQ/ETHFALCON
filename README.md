# ETHFALCON

ETHFALCON gather experimentations around FALCON adaptations for the ETHEREUM ecosystem. [Falcon signature scheme](https://falcon-sign.info/) is a post-quantum digital signature algorithm. 
This repo provides:

* on-chain [contracts](https://github.com/ZKNoxHQ/ETHFALCON/tree/main/src) for verification
* [python](https://github.com/ZKNoxHQ/ETHFALCON/tree/main/pythonref) signers and verification for testing (offchain and on-chain wrapping cast).
* [c](https://github.com/ZKNoxHQ/ETHFALCON/tree/main/falcon/nistfalcon) signers and verification for testing (based on the NIST reference implementation, with added functionalities).

**This is an experimental work, not audited: DO NOT USE IN PRODUCTION, LOSS OF FUND WILL OCCUR.**

## SPECIFICATION

The repo implements several versions of FALCON:

* FALCON is the legacy NIST round3 compliant (tested against the 100 official [KATS](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/round-3-submissions) in [test/falcon_KAT_file.t.sol](https://github.com/ZKNoxHQ/ETHFALCON/blob/main/test/falcon_KAT_file.t.sol), plus single vectors in [test/falconKATS.t.sol](https://github.com/ZKNoxHQ/ETHFALCON/blob/main/test/falconKATS.t.sol)).

* ETHFALCON is an EVM friendly version, security equivalent replacing SHAKE by keccak to reduce costs (100 KAT vectors in [test/ethfalcon_KAT_file.t.sol](https://github.com/ZKNoxHQ/ETHFALCON/blob/main/test/ethfalcon_KAT_file.t.sol)).

* EPERVIER is a 'FALCON with recovery' EVM version, enabling to mimic the ecrecover functionning (recover address from signature).


Detailed specification is provided in the [EIP 8052](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-8052.md) and [here](./doc/specification.md). 


## I/O Description

This section describes the mathematical encodings used in ZKNOX implementation and NIST.

### Polynomials representations:


#### Expanded polynomials 

Expanded polynomials are arrays sorted from lowest to highest degree, thus a polynomial $P=a_0+a_1X+...+a_{511}X^{511}$ is encoded as the array $$A=[a0, ..., a_{511}]$$

#### Compacted polynomials 

Polynomials in FALCON512 are polynomial of degree 511 defined over $F_{12289}$. As such they are represented by packing 16 coefficients of 16 bits by word, thus a polynomial $P=a_0+a_1X+...+a_{511}X^{511}$ is encoded as the uin256 array $$A=[a0+2^{16}a_1+ ...+2^{16\times 15}a_{15}, ..., a_{240}+ ...+2^{16\times 15}a_{511}]$$

Conversion from and to compact/expanded polynomials are performed by ```_ZKNOX_NTT_Expand``` and ```_ZKNOX_NTT_Compact```. On chain external functions use compacted representation to reduce call data cost.

##### NTT and standard representation

The NTT (frequency) domain is used to speed up polynomial multiplication. Switching to and from the NTT domain is performed using ```_ZKNOX_NTTFW``` and ```_ZKNOX_NTTINV```. Those operation are the most expensive, thus the verification functions takes the public key in its NTT representation.




#### Compressed polynomials

Compressed polynomials uses a custom RLE encoding defined in  [Algorithm 17](https://falcon-sign.info/falcon.pdf) of FALCON specification. 
Decompression of polynomials is performed by ```_ZKNOX_NTT_Decompress```.

#### NIST KATS

NIST KAT are made of

     * the encoded public key:0x09+ public key compressed value
     * the signature bundled with the message. Format is:
	 *   signature length     slen encoded on 2 bytes, big-endian
	 *   nonce                40 bytes
	 *   message              mlen bytes
	 *   signature            slen bytes

Conversion from NIST KATS to ZKNOX encodings are performed by  ```decompress_KAT``` (`src/ZKNOX_falcon_encodings.sol`, a test helper, not used by the verifiers). It decodes strictly, as the NIST reference `crypto_sign_open`: `slen` must match the actual length (no trailing bytes), the compressed s2 must use exactly `slen - 1` bytes with zero padding bits and no "-0" coefficient, and the public key must be exactly 897 bytes. The public key it returns is in coefficient form: apply `_ZKNOX_NTTFW_vectorized` before compacting it into `ntth`.

#### Keys from the ZKNOX C signer

The ZKNOX C signer (`falcon/nistfalcon`, `zknox_crypto_sign_keypair*`, and `falcon/falcon.js`) outputs the public key **already in the NTT domain**: `0x09 || ntt(h)[i]` as 512 big-endian 16-bit words. Compact those words as-is into `ntth` (see `test/falconKATS.t.sol::test_kats_vector0_from_c`); applying the NTT again yields a key that rejects every signature.

## INTEGRATION NOTES

* **Public keys (`setKey` / ERC-7913).** `setKey(abi.encode(ntth))` stores the key in an SSTORE2 data contract and returns its 20-byte address, which is the ERC-7913 key passed to `verify(bytes pubkey, bytes32 digest, bytes sig)`. `setKey` is permissionless and only checks the key encoding (canonical `abi.encode(uint256[32])`, every coefficient `< q`): the account must store the returned pointer itself, and a key is only as trusted as that pointer. `verify` rejects a `pubkey` that is not exactly 20 bytes or that does not point to such a data contract. The same `ntth` can sit behind several pointers: deduplicate on `keccak256(ntth)` if key uniqueness matters (e.g. multisig).
* **No domain binding.** No verifier binds the chain id, the verifying contract or a nonce, and a FALCON signature and an EPERVIER signature for the same key convert into each other (an EPERVIER signature for address A is a valid `ZKNOX_falcon` signature under the matching `ntth`, and conversely whenever `ntt(s2)` has no zero coefficient; same for ETHFALCON / ETHEPERVIER). Callers **must** put the domain (chain id, account, nonce, purpose) inside the signed message to prevent replay across chains, accounts and schemes.
* **Failure semantics.** `verify(h, salt, s2, ntth)` reverts on malformed lengths (salt not 40 bytes, s2 or ntth not 32 words) and returns `false` for an invalid signature (including an out-of-range s2 coefficient or a public key coefficient `>= q`). The ERC-7913 `verify(pubkey, digest, sig)` reverts on a malformed `pubkey` or `sig` length and returns `0xFFFFFFFF` for an invalid signature. EPERVIER `recover` always **reverts** on invalid input or signature (out-of-range coefficients, norm too large, wrong or non-canonical hint, which must satisfy `0 < hint < q`); unlike `ecrecover`, it never returns `address(0)`. Wrap the call (`try`/`catch` or a low-level call) if a boolean result is needed.
* **Messages.** `h` / `msgs` is the raw message, of any length: it is hashed together with the 40-byte salt by the hash-to-point (`SHAKE256(salt || msg)` or Keccak-CTR), so there is no need to pre-hash it.


## INSTALLATION


The repo contains a solidity verifier and a python signer. 

* **Installation:**
    ```bash
    make install
    ```
    (or `make install_signer` or `make install_verifier`)

* **Tests:**
    ```bash
    make test
    ```
    (or `make test_signer` or `make test_verifier`)

## BENCHMARKS

The following benchmarks can be reproduced using 
```bash
make bench
```

| Function                   | Description               | gas cost | Tests Status |
|------------------------|---------------------|---------------------|---------------------|
| ZKNOX_falcon.verify       | NIST       | 3.8M | :white_check_mark:|
| ZKNOX_ethfalcon.verify       | EVM Friendly      | 1.4 M | :white_check_mark:|
| ZKNOX_ethepervier.recover       | Recover EVM friendly      | 1.6 M | :white_check_mark:|


### Experimental (branches `exp/pq-verifier-gas` and `exp/falcon1024`, not on `main`)

Not reproducible with `make bench` on this branch: check out
`exp/pq-verifier-gas` (Falcon-512) or `exp/falcon1024` (Falcon-1024, built on
top of the former) first. Both change the build profile (solc 0.8.30, via-IR,
`optimizer_runs = 1000000`, evm cancun), so their bytecode differs from
`main`'s for every contract.

| Function | Description | gas cost | Tests Status |
|---|---|---|---|
| ZKNOX_falcon_fast.verify | NIST, SHAKE256 via an external Keccak-f[1600] helper | 1,975,365 | :white_check_mark: |
| ZKNOX_falcon_turbo.verify | NIST, the above + a packed-SWAR NTT core | 1,315,105 | :white_check_mark: |
| ZKNOX_falcon_fused.verify | NIST, the above + fused radix-8 NTT, Yul hash-to-point sampler, SWAR norms | 726,900 | :white_check_mark: |
| ZKNOX_falcon8.verify | NIST, eight 32-bit lanes with Montgomery R = 2^16, product in the subrings X^8 - zeta_w (key given in that form, one mul / mulmod per word), sixteen-candidate sampler on 16-bit fields with the norm folded into hash-to-point, resident SHAKE lanes, own Keccak-f[1600] helper | **447,047** | :white_check_mark: |
| ZKNOX_falcon1024.verify (`exp/falcon1024`) | NIST Falcon-1024 (round 3 KATs), same chain, product, sampler and helper | **845,839** (KAT 0; mean over KAT 0..9 861,147, max 910,068) | :white_check_mark: |

The gas cost is the execution of `verify` measured from the test contract on
the NIST KAT (helper's EXTCODEHASH and its 9 or 17 permutation calls
included, transaction base and calldata not): **8.75x** from `ZKNOX_falcon`
(3,910,833 on `main` when measured; 3,770,636 since the 2026-11-16 audit
fixes, i.e. 8.4x). As a plain transaction
(`verify(bytes h, bytes salt, uint256[] s2, uint256[] ntth)`, 16/4 gas per
calldata byte):

| | Falcon-512 (`ZKNOX_falcon8`) | Falcon-1024 (`ZKNOX_falcon1024`) |
|---|---:|---:|
| execution | 447,047 | 845,839 |
| calldata (2,404 / 4,484 bytes) | 32,320 | 62,444 |
| base | 21,000 | 21,000 |
| total | ~500,400 | ~929,300 |

All verifiers keep the `verify(h, salt, s2, ntth)` API of `ZKNOX_falcon`;
the eight-lane ones take the key in its partial NTT form (the residues of h
mod X^8 - zeta_w after the aligned NTT layers, two residues interleaved per
word, produced by `pythonref/gen_falcon_vectors.py` from a public key) and
run the 100 NIST round-3 KAT vectors of their size with the exact squared
norm (`test/falcon512_vectors.json`, `test/falcon1024_vectors.json`,
re-verified by noble in `jsref/check_falcon_kat.mjs`), plus differential
fuzz against `ZKNOX_falcon` on both sides of the signature bound (158 tests
on `exp/pq-verifier-gas`, 179 on `exp/falcon1024`).

Where the gas goes (`pythonref/profile_evm.py`, opcode-level profile of the
`verify` frame in py-evm): the Keccak-f[1600] permutations of hash-to-point
are 69 % of Falcon-512 (9 x 32,979) and 67 % of Falcon-1024 (17 x 32,979);
the rest is the product s1 = INTT(NTT(s2) o NTT(h)) (76K / 161K), the
sampler with the norm folded in (37K / 74K) and the norm of s2 (12K / 24K).
The permutation count is fixed by the specification and the per-round cost
of the helper (1,350 gas) is at the floor of its stack representation, so
the next step is a precompile, not more Solidity.

The NIST verifiers of the branches delegate the Keccak-f[1600] permutation
to a helper contract bound by `EXTCODEHASH`, deployed once per chain and
shared. `ZKNOX_falcon_fast`, `_turbo` and `_fused` use the Fireblocks helper
(MIT, vendored from fireblocks-labs/evm-ml-dsa-verifier,
`test/f1600_170.hex`); `ZKNOX_falcon8` and `ZKNOX_falcon1024` use our own
(`test/f1600_zknox.hex`, 21,531 bytes, generated by
`pythonref/gen_keccak_helper.py`: two-opcode rotations, ten lanes kept on
the stack, 32,829 gas per permutation against 40,448, checked against the
Fireblocks helper on both of its interfaces and against a Python reference
on a gas-counting mini-EVM). See `DECISIONS.md` (ADR-001 to ADR-014) and
`VERSION.md` on the branches for the measurements, the bounds and what was
tried and rejected.

More benchmark details for both solidity code and python  available [here](./doc/benchmarks.md).
Those are measured on compacted polynomial representation. For decompressed/kats, add 900K to benchmarks.

## EXAMPLE


Use the following commands to generate, sign a message and verify it with the onchain contract
```bash
# generate public and private keys using 'falcon', 'ethfalcon' or 'epervier'
./sign_cli.py genkeys --version='falcon'
# generate a signature
./sign_cli.py sign --privkey='private_key.pem' --data=546869732069732061207472616e73616374696f6e
# verify onchain the  signature using address of contract specified below (ensure --version is compliant with address)
./sign_cli.py verifyonchain --pubkey='public_key.pem' --data=546869732069732061207472616e73616374696f6e --signature='sig' --contractaddress='0xD088Ede58BD1736477d66d114D842bDE279A41Fa' --rpc='https://sepolia.optimism.io'w
```
The contract address refers to the contract implementing FALCON in Solidity. This should output:
```
0x0000000000000000000000000000000000000000000000000000000000000001
```
More details [here](./doc/example.md).

https://ethresear.ch/t/lattice-based-signature-aggregation/22282
https://github.com/leanEthereum/leanSpec/pull/9
https://github.com/leanEthereum/leanMultisig/tree/main/crates/leanVm

## DEPLOYMENTS

Contract deployments are provided in [kohaku project](https://github.com/ethereum/kohaku/blob/master/packages/pq-account/deployments/deployments.json).


## 7702 DELEGATION

Before Native Account Abstraction is pushed, FALCON can be integrated in a 7702 delegation through the ERC-7913 `verify(bytes pubkey, bytes32 digest, bytes sig)` entry point of `ZKNOX_falcon` / `ZKNOX_ethfalcon` (see [Integration notes](#integration-notes); it also works when reached through `DELEGATECALL`).

One of Kohaku goals is to integrate these contracts in a 4337 account.

## SECURITY
This repository has not been audited. We ran internal audits, and we also thank external developers for their review of the code (@007bsd for finding a vulnerability in the salt computation in some od the signers).

## CONCLUSION

This repo provides a highly optimized version of FALCON. Order of magnitudes were gained compared to other implementations. In our search, we also devise a way to implement falcon with recovery without requiring the inverse NTT transformation (only forward).
Despite those efforts, it does not seem plausible to reach operational (below 1M) verification cost. Nevertheless, the provided code allow Account Abtraction using 7702 or 4337 from today.
The architecture also demonstrates that providing NTT would allow an acceptable cost, and provide more genericity and agility in the PQ signature candidate of Ethereum. For this reason [NTT-EIP]() is submitted.

## REFERENCES
- [[EXTCODE COPY TRICK]](https://eprint.iacr.org/2023/939) section 3.3
- [[FALCON]](https://falcon-sign.info/falcon.pdf) Falcon: Fast-Fourier Lattice-based
Compact Signatures over NTRU
- [[NTT-EIP]]() NTT-EIP as a building block for FALCON, DILITHIUM and Stark verifiers 
- [[Tetration]](https://github.com/Tetration-Lab/falcon-solidity/blob/main/src/Falcon.sol) Falcon solidity.
