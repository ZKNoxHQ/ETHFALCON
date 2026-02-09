
### Solidity


| Function                   | Description               | gas cost | Tests Status |
|------------------------|---------------------|---------------------|---------------------|
| falcon.verify       | original gas cost from [falcon-solidity](https://github.com/Tetration-Lab/falcon-solidity/blob/main/src/Falcon.sol)         | 24M | OK|
| falcon.verify      | ZKNOX fork, recursive NTT | 20.8 M| OK|
| falcon.verify_opt         | Use of precomputed NTT public key form, recursive NTT | 14.6 M| OK|
| falcon.verify_iterative         | Use of precomputed NTT public key form, custom iterative NTT | 8.3 M| OK|




### Yul

Upon confirmation of the optimal algorithm for NTT, its critical parts have been implemented in Yul, benefiting from the extcodecopy trick described in 3.3, stack optimization, and variable control. The function verifyNIST is compliant to NIST signatures after decompression. As SHAKE is $70\%$ of computations, a EVM equivalent is proposed (using keccak).



| Function                   | Description               | gas cost | Tests Status |
|------------------------|---------------------|---------------------|---------------------|
| ZKNOX_falcon.verify       | NIST       | 3.9M | :white_check_mark:|
| ZKNOX_ethfalcon.verify       | EVM Friendly      | 1.6 M | :white_check_mark:|
| ZKNOX_epervier.verify       | Recover EVM friendly      | 1.5 M | :white_check_mark:|



**Note on the encoding**: polynomials are encoded as $(a_0 || a_1|| \ldots|| a_k)$, where $P=\sum {a_i}X^i$, the operator || being concatenation, each $a_i$ being encoded on 16 bits. This leads to a representation of $P$ over 32 uint256.
