# Falcon in python

This repository implements the signature scheme Falcon (https://falcon-sign.info/).
Falcon stands for **FA**st Fourier **L**attice-based **CO**mpact signatures over **N**TRU

**Authors: Renaud Dubois and Simon Masson.**

<small>Acknowledgements: Thomas Prest for the originial code, Zhenfei Zhang for the possible optimizations.</small>

:warning: This is an experimental code, not the [reference code](https://falcon-sign.info/) of Falcon.. It is not considered secure or suitable for production. 

License: MIT.

## Interface

It is possible to generate a key pair, sign a message and verify a signature in one command-line.

Supported versions (the version is stored in the key files, and every action uses it):

| version     | hash-to-point | public key                      |
|-------------|---------------|---------------------------------|
| `falcon`    | SHAKE256      | h (512 coefficients)            |
| `ethfalcon` | KeccakPRNG    | h (512 coefficients)            |
| `epervier`  | SHAKE256      | address derived from NTT(h)     |
| `falconrec` | KeccakPRNG    | address derived from h          |

An unknown version is an error.

###### Key generation


```
./sign_cli.py genkeys --version='falcon' # or 'ethfalcon', 'epervier', 'falconrec'
```
It creates two files in the current directory: `private_key.pem` and `public_key.pem`.
- `private_key.pem` holds the secret key (f, g, F, G) **in plaintext**. It is created with mode `0600` (readable by you only), whatever your umask. Keep it out of version control: the repository `.gitignore` ignores `private_key.pem` and `public_key.pem` everywhere.
- `genkeys` refuses to overwrite an existing `private_key.pem` or `public_key.pem`; pass `--force` to replace them.

Nothing is printed in Solidity format; use `sign_tx` below to get the on-chain arguments.

When a secret key file is loaded, it is validated (f·G − g·F = q, f invertible mod q, h = g/f matches the stored public key, Gram-Schmidt norm and sampler bounds), and a warning is printed if the file is readable by other users.

###### Signature
```
./sign_cli.py sign --data=deadbeef --privkey=private_key.pem
```
It creates a signature file `sig` (hexadecimal) for the given message and private key. Every signature is verified before it is written.

The salt and the sampler randomness are derived from the **secret** key:
`SHAKE256(domain || mode || version || f, g, F, G || entropy || message)`.
- Default, *hedged*: `entropy` is 32 fresh bytes from `os.urandom`. Signing the same message twice gives two different signatures.
- `--deterministic`: no fresh entropy. The signature is reproducible for a given key, version and message, and the randomness stays secret (it never depends on the public key alone). Only use it when reproducibility is needed.

###### Verification
```
./sign_cli.py verify --data=deadbeef --pubkey=public_key.pem --signature='sig'
```
It outputs the validity of the signature with respect to a message and a public key given as input (exit code 1 if invalid).
Only the canonical encoding is accepted: the header byte (`0x29` for FALCON/ETHFALCON, `0x39` for EPERVIER/recovery), a full 40-byte salt, coefficients |x| ≤ 2047, zero padding, and, in the recovery modes, hint entries < q. Malformed input is rejected without raising.

###### Transaction signature
```
./sign_cli.py sign_tx --privkey=private_key.pem --data=00 --nonce=01 --to=<address> --value=00
```
It signs `keccak256(abi.encode(nonce, to, data, value))` with the key's version and prints the arguments of the on-chain call (`PK`, `S2`, `SALT` for FALCON/ETHFALCON; `ADDRESS`, `S1`, `S2`, `HINT`, `SALT` for EPERVIER).

###### On-chain verification
```
./sign_cli.py verifyonchain --data=deadbeef --pubkey=public_key.pem --signature=sig --contractaddress=0x... --rpc=https://...
./sign_cli.py recoveronchain --data=deadbeef --pubkey=public_key.pem --signature=sig --contractaddress=0x... --rpc=https://...
```
These run a read-only `cast call`. For EPERVIER, `verifyonchain` prints the recovered and the expected address, then `MATCH` or `MISMATCH`.

`verifyonchainsend` and `recoveronchainsend` send a transaction with `cast send`, so they need an Ethereum (ECDSA) wallet. The private key never appears on a command line:
- `--account NAME` (a cast keystore in `~/.foundry/keystores`) or `--keystore PATH`, optionally with `--password-file`, is passed through to cast, which decrypts the keystore itself (recommended);
- otherwise the key is read from the `ETH_PRIVATE_KEY` environment variable. cast has no environment variable for a raw key, so the CLI writes it to a temporary encrypted keystore (mode `0600`, in a `0700` directory, with a random password) for the duration of the `cast send` call and deletes it right after.

```
read -s ETH_PRIVATE_KEY && export ETH_PRIVATE_KEY
./sign_cli.py verifyonchainsend --data=deadbeef --pubkey=public_key.pem --signature=sig --contractaddress=0x... --rpc=https://...
```
`--privatekey` still works but is deprecated: the key is then visible in the process list and in your shell history.

All external commands are run with an argument list (no shell); the RPC URL is passed as a single `--rpc-url=<value>` argument, and the contract address must be `0x` followed by 40 hex digits.


<!-- ## Profiling

I included a makefile target to performing profiling on the code. If you type `make profile` on a Linux machine, you should obtain something along these lines:

![kcachegrind](https://tprest.github.io/images/kcachegrind_falcon.png)

Make sure you have `pyprof2calltree` and `kcachegrind` installed on your machine, or it will not work. -->

## Tests

Tests of key generation, signing and verification can be done in iterative and recursive NTT. The HashToPoint can be set with the SHAKE256, KeccaXOF (implemented in Tetration), or KeccakPRNG (a PRNG based on Keccak).
```
make test
```
This runs the original tests, the additional tests made in `test_xxx.py`, and `forgery.py`.

`forgery.py` demonstrates the salt/message concatenation ambiguity (CVETH-2025-080201): with a variable-length salt, a signature on `(message, salt)` also verifies for `(salt || message, "")`. It checks that the 40-byte salt required by every verifier of this repository (Python and Solidity) defeats the attack.

The KeccakPRNG and Blake2sPRNG absorb their input incrementally, so there is no limit on the message length (as in `hashToPointEVM`).

## Benchmarks

:warning: This implementation is not optimized.

<table>
  <tr>
    <th rowspan="2">n</th>
    <th colspan="2">Key generation</th>
    <th colspan="2">Signature</th>
    <th colspan="4">Verification</th>
  </tr>
  <tr>
    <td>NTT iterative</td>
    <td>NTT recursive</td>
    <td>SHAKE256</td>
    <td>KeccaXOF</td>
    <td>NTT iterative</td>
    <td>NTT recursive</td>
    <td>SHAKE256</td>
    <td>KeccaXOF</td>
  </tr>
  <tr>
    <td>64</td>
    <td>180 ms</td>
    <td>96 ms</td>
    <td>2.4 ms</td>
    <td>2.4 ms</td>
    <td>0.3 ms</td>
    <td>0.6 ms</td>
    <td>0.3 ms</td>
    <td>0.4 ms</td>
  </tr>
  <tr>
    <td>128</td>
    <td>825 ms</td>
    <td>1033 ms</td>
    <td>4.7 ms</td>
    <td>4.7 ms</td>
    <td>0.6 ms</td>
    <td>1.4 ms</td>
    <td>0.6 ms</td>
    <td>0.7 ms</td>
  </tr>
  <tr>
    <td>256</td>
    <td>1051 ms</td>
    <td>1530 ms</td>
    <td>9.7 ms</td>
    <td>9.4 ms</td>
    <td>1.3 ms</td>
    <td>3.0 ms</td>
    <td>1.3 ms</td>
    <td>1.3 ms</td>
  </tr>
  <tr>
    <td>512</td>
    <td>2273 ms</td>
    <td>1755 ms</td>
    <td>19.2 ms</td>
    <td>19.0 ms</td>
    <td>3.0 ms</td>
    <td>6.6 ms</td>
    <td>3.0 ms</td>
    <td>3.0 ms</td>
  </tr>
  <tr>
    <td>1024</td>
    <td>10256 ms</td>
    <td>13652 ms</td>
    <td>39.3 ms</td>
    <td>39.2 ms</td>
    <td>6.4 ms</td>
    <td>14.2 ms</td>
    <td>6.4 ms</td>
    <td>6.2 ms</td>
  </tr>
</table>
