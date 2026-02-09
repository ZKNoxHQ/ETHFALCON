# ETHFALCON

ETHFALCON gather experimentations around FALCON adaptations for the ETHEREUM ecosystem. [Falcon signature scheme](https://falcon-sign.info/) is a post-quantum digital signature algorithm. 
This repo provides:

* on-chain [contracts](https://github.com/ZKNoxHQ/ETHFALCON/tree/main/src) for verification
* [python](https://github.com/ZKNoxHQ/ETHFALCON/tree/main/pythonref) signers and verification for testing (offchain and on-chain wrapping cast).
* [c](https://github.com/ZKNoxHQ/ETHFALCON/tree/main/falcon/nistfalcon) signers and verification for testing (based on the NIST reference implementation, with added functionalities).

**This is an experimental work, not audited: DO NOT USE IN PRODUCTION, LOSS OF FUND WILL OCCUR.**

## SPECIFICATION

The repo implements several versions of FALCON:

* FALCON is the legacy NIST round3 compliant (tested against official [KATS](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/round-3-submissions), just [here](https://github.com/ZKNoxHQ/ETHFALCON/blob/8152c5fc770e863bec799b5cc21dd551ab585fd9/test/ZKNOX_falconKATS.t.sol#L73)).

* ETHFALCON is an EVM friendly version, security equivalent replacing SHAKE by keccak to reduce costs.

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

Conversion from NIST KATS to ZKNOX encodings are performed by  ```decompress_KAT. ```


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
| ZKNOX_falcon.verify       | NIST       | 3.9M | :white_check_mark:|
| ZKNOX_ethfalcon.verify       | EVM Friendly      | 1.5 M | :white_check_mark:|
| ZKNOX_epervier.verify       | Recover EVM friendly      | 1.6 M | :white_check_mark:|


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

Before Native Account Abstraction is pushed, a demonstration of how to integrate FALCON in a 7702 delegation is provided in ZKNOX_IVerifierDelegate_7702.t.sol.

One of Kohaku goals is to integrate these contracts in a 4337 account.

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
