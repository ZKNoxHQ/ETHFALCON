# ETHFALCON

ETHFALCON gather experimentations around FALCON adaptations for the ETHEREUM ecosystem. [Falcon signature scheme](https://falcon-sign.info/) is a post-quantum digital signature algorithm. 
This repo provides:

* on-chain [contracts](https://github.com/ZKNoxHQ/ETHFALCON/tree/main/src) for verification
* [python](https://github.com/ZKNoxHQ/ETHFALCON/tree/main/python-ref) signers and verification for testing (offchain and on-chain wrapping cast).



## SPECIFICATION

The repo implements several versions of FALCON:

* FALCON is the legacy NIST round3 compliant (tested against official [KATS](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/round-3-submissions), just [here](https://github.com/ZKNoxHQ/ETHFALCON/blob/8152c5fc770e863bec799b5cc21dd551ab585fd9/test/ZKNOX_falconKATS.t.sol#L73)).

* ETHFALCON is an EVM friendly version, security equivalent replacing SHAKE by keccak to reduce costs.

* EPERVIER is a 'FALCON with recovery' EVM version, enabling to mimic the ecrecover functionning (recover address from signature).


Detailed specification is [here](./doc/specification.md). 


## INSTALLATION

**This is an experimental work, not audited: DO NOT USE IN PRODUCTION, LOSS OF FUND WILL OCCUR**

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


| Function                   | Description               | gas cost | Tests Status |
|------------------------|---------------------|---------------------|---------------------|
| ZKNOX_falcon.verify       | NIST       | 7M | :white_check_mark:|
| ZKNOX_ethfalcon.verify       | EVM Friendly      | 1.9 M | :white_check_mark:|
| ZKNOX_epervier.verify       | Recover EVM friendly      | 1.9 M | :white_check_mark:|


More details for both solidity code and python are available [here](./doc/benchmarks.md).

## EXAMPLE


Use the following commands to generate, sign a message and verify it with the onchain contract
```bash
# generate public and private keys using 'falcon' or 'ethfalcon'
./sign_cli.py genkeys --version='falcon'
# generate a signature for the message "This is a demo"
./sign_cli.py sign --privkey='private_key.pem' --data=546869732069732061207472616e73616374696f6e
# verify onchain the  signature using address of contract specified below (ensure --version is compliant with address)
./sign_cli.py verifyonchain --pubkey='public_key.pem' --data=546869732069732061207472616e73616374696f6e --signature='sig' --contractaddress='0x5dc45800383d30c2c4c8f7e948090b38b22025f9' --rpc='https://ethereum-holesky-rpc.publicnode.com'
```
The contract address refers to the contract implementing FALCON in Solidity. This should output:
```
0x0000000000000000000000000000000000000000000000000000000000000001
```
More details [here](./doc/example.md).



## DEPLOYMENTS

Current deployment addresses:

| Function                   | Description               |address | testnets | mainnets | commit |
|------------------------|---------------------|---------------------|---------------------|---------------------|----------------|
| EPERVIER     | Epervier      | TBD | Holesky| | | 
| ETHFALCON     | ETHFalcon implementation      | 0xC916569fcdf68CdD11229a98e9981664DBb79A2d | Holesky | [Optimism](https://optimistic.etherscan.io/address/0xC916569fcdf68CdD11229a98e9981664DBb79A2d) |[c0d465794f67044ddd19f73c21acd9570e9e578b](https://github.com/ZKNoxHQ/ETHFALCON/commit/c0d465794f67044ddd19f73c21acd9570e9e578b) | 
| FALCON     | Falcon NIST Legacy implementation      | [0x5dc45800383d30c2c4c8f7e948090b38b22025f9](https://holesky.etherscan.io/address/0x5dc45800383d30c2c4c8f7e948090b38b22025f9) | [Holeski](https://holesky.etherscan.io/address/0x5dc45800383d30c2c4c8f7e948090b38b22025f9), [Optimism (Sepolia)](https://sepolia-optimism.etherscan.io/address/0x5dC45800383D30c2C4C8f7e948090b38B22025f9), [Base Sepolia](https://sepolia.basescan.org/address/0x5dC45800383D30c2C4C8f7e948090b38B22025f9#code)| [Optimism](https://optimistic.etherscan.io/address/0x5dc45800383d30c2c4c8f7e948090b38b22025f9#code), [L1 (mainnet)](https://etherscan.io/address/0x5dc45800383d30c2c4c8f7e948090b38b22025f9#code) | [c0d465794f67044ddd19f73c21acd9570e9e578b](https://github.com/ZKNoxHQ/ETHFALCON/commit/c0d465794f67044ddd19f73c21acd9570e9e578b) | 


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
