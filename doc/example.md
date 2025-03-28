
# EXAMPLE OF USE

**This is an experimental work, not audited: DO NOT USE IN PRODUCTION, LOSS OF FUND WILL INCUR**

## ETHFALCON

A signature is generated using Python and verified using Solidity following those steps.
```bash
cd python-ref
make install
```
The public and private keys are generated using Python:
```bash
# generate public and private keys
./sign_cli.py genkeys --version='ethfalcon'
```
The signature is computed from the private key (stored in `private_key.pem`):
```bash
# generate a signature for the message "This is a demo"
./sign_cli.py sign --privkey='private_key.pem' --data=546869732069732061207472616e73616374696f6e
```
The signature can be verified on chain:
```bash
./sign_cli.py verifyonchain --pubkey='public_key.pem' --data=546869732069732061207472616e73616374696f6e --signature='sig' --contractaddress='0xD2d8e3a5bCf8E177A627698176bC9a99E03D358D' --rpc='https://ethereum-holesky-rpc.publicnode.com'
```
The contract address refers to the contract implementing ETHFALCON in Solidity. This should output:
```
0x0000000000000000000000000000000000000000000000000000000000000001
```

## FALCON NIST

We can also use the NIST version of FALCON. It works very similarly.

The public and private keys are generated with:
```bash
# generate public and private keys
./sign_cli.py genkeys --version='falcon'
```
The signature is computed from the private key (stored in `private_key.pem`):
```bash
# generate a signature for the message "This is a demo"
./sign_cli.py sign --privkey='private_key.pem' --data=546869732069732061207472616e73616374696f6e
```
The signature can be verified on chain:
```bash
./sign_cli.py verifyonchain --pubkey='public_key.pem' --data=546869732069732061207472616e73616374696f6e --signature='sig' --contractaddress='0x5dc45800383d30c2c4c8f7e948090b38b22025f9' --rpc='https://ethereum-holesky-rpc.publicnode.com'
```
The contract address refers to the contract implementing FALCON in Solidity. This should output:
```
0x0000000000000000000000000000000000000000000000000000000000000001
```

___
___
## Transaction output

For computing a transaction, we need to provide:
* A `nonce`, unique identifier as a `uint256` given in hex,
* The destination address `to`, a `uint160` given in hex,
* The transaction `data` to be signed, given in hex,
* The value as an integer given in decimal.

For the signature, we also need to provide:
* The private key file,
* The version of the scheme (it works only for `falcon` for now),
```bash
./sign_cli.py sign_tx --data=546869732069732061207472616e73616374696f6e --privkey=private_key.pem --version='ethfalcon' --nonce=0123456789 --to=add4e55 --value=123
```
This outputs the useful data for the transaction:
* The hash for the transaction`TX_HASH`: `Keccak256(nonce|to|data|value)`,
* The signature `S2` in compact form,
* The `SALT` value,
* The public key `PK` in NTT in compact form.
