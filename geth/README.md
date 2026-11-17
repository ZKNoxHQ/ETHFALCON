# Geth recipee for falcon Minimal fork

This directory contains the minimal sources to have a forked geth including a Falcon Precompile.


- Compile ETHFALCON/falcon go bindings

 ```bash
make go
 ```

- Clone geth repository

```bash
git clone https://github.com/ethereum/go-ethereum.git
 ```

- Replace contracts.go by the forked version of this directory
```bash
mv contracts.go $YOURGETH/core/vm/contracts.go
 ```


- Provide falcon go module to geth
```bash
go clean -modcache
go get github.com/ZKNoxHQ/ETHFALCON/falcon@latest
go mod tidy
 ```

- Compile geth
```bash
make geth
 ```


- Run geth in dev mode:
```bash
./build/bin/geth --http --http.api eth,net,web3 --http.addr 127.0.0.1 --http.port 8547 --dev
 ```


- Run example with cast:

    * generate example (prints `SIG=…`, `MSG=…`, `PUB=…`)

```bash
cd ../test/go && go run test_falconmodule.go
 ```

    * run example

```bash
cast call 0x0000000000000000000000000000000000000013 "$(cast abi-encode "falconvrfy(bytes,bytes,bytes)" $SIG $MSG $PUB)" --rpc-url http://localhost:8547
 ```

0x13 is the precompile address (subject to change with next forks).

## Precompile interface

- Input: `abi.encode(bytes signedMessage, bytes message, bytes publicKey)` (no function selector).
    * `signedMessage` is the NIST `crypto_sign` output: 2-byte signature length, 40-byte nonce, message, compressed signature (as returned by `falcon.SignMessage`).
    * `publicKey` is the 897-byte NIST Falcon-512 public key.
    * This is the plain NIST format, not the ETHFALCON/EPERVIER format used by the Solidity verifiers.
- Output: 32 bytes, `1` if the signature is valid for `message` under `publicKey`, `0` otherwise. A wrong-length key, a truncated or malformed signature, or a message mismatch returns `0`. Input that is not valid ABI makes the call fail.
- Gas: flat 3000 (`RequiredGas`), whatever the input length. The verification cost grows with the length of the signed message, which is hashed; the price does not reflect that yet.

## Tests

The Go binding tests live in `test/go`. Build the C library first (`make go` in `falcon/`), then:

```bash
cd test/go
go test -race ./...
```
