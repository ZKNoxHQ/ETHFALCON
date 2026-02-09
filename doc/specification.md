# SPECIFICATION 

The repository implements several tweaked version of FALCON, optimized for different constraints. In the rest of this note, the following versions will be distinguished:


<table>
  <tr>
    <th>Algorithm</th>
    <th>Specification</th>
    <th>Description</th>
    <th>Implementation Status </th>
  </tr>
  <td>FALCON</td>
  <td>NIST</td>
  <td>The original FALCON NIST submission</td>
  <td> OK</td>
    </tr>
  <td>FALCONREC</td>
  <td>NIST</td>
  <td>The original FALCON NIST submission, recovery mode</td>
  <td>OK</td>
  </tr>
  <td>FALCON-SOLIDITY</td>
  <td>Tetration </td>
  <td>An EVM Friendly version of FALCON using keccak instead of SHAKE for XOF</td>
  <td> OK </td>
  </tr>
  </tr>
   <td>FALCON-SOLREC</td>
  <td>Tetration </td>
  <td>A  recovery version, compatible with FALCON SOLIDITY XOF</td>
  <td> OK </td>
  </tr>
  <td>FALCONEVM</td>
  <td>ASANSO </td>
  <td>FALCON EVM draft by [ASANSO](https://github.com/asanso/RIPs/blob/master/RIPS/rip-falcon.md) </td>
  <td> OK </td>
  </tr>
  <td>EPERVIER</td>
  <td>ZKNOX </td>
  <td>An EVM Friendly version of FALCONREC  avoiding expensive operations </td>
  <td> OK</td>
  </tr>

</table>   

The difference lies mainly in the definition of the inner expandable hash functions (XOF) required in $HashToPoint$ and $H$ (this latest only for recovery).
Those function being non standard, the  code provided by authors is the specification until further notice.
<table>
  <tr>
    <th>Algorithm</th>
    <th> XOF </th>
    <th> H </th>
  </tr>
  <td> FALCON </td>
  <td> SHAKE</td>
  <td> N/A </td>
  </tr>
  </tr>
    <td> FALCON-SOLIDITY </td>
    <td> Keccak-OFB </td>
    <td> N/A </td>
  </tr>
   </tr>
    <td> FALCONEVM </td>
    <td> Keccak-CTR </td>
    <td> N/A </td>
  </tr>
 </tr>
  <td> EPERVIER </td>
  <td> Keccak-CTR (WIP) </td>
  <td> Keccak(NTT(x)) </td>
  </tr>


</table>     

### Falcon 

**Original specification.** 
FALCON refers to the original [specification](https://falcon-sign.info/falcon.pdf), as submitted to NIST. We provide here a simplified description of the signature scheme:
- The public key is a polynomial $h$,
- The signature is given as $(s_2, r)$ where $s_2$ is in compressed format,
- The verification is split as follows:
  - $c\leftarrow HashToPoint(r||m)$,
  - Decompress $s_2$ (reject if it goes wrong),
  - $s_1 \leftarrow c-s_2\times h$,
  - if $(s_1,s_2)$ is short, accept, otherwise, reject.

**Public key recovery mode.**
Falcon specification also includes a public key recovery version. Although it is not present in the standard implementation, it is described in the specification in [Section 3.12](https://falcon-sign.info/falcon.pdf). We denote this version FalconRec and we summarize it here:
- The public key becomes $pk=H(h)$ for some collision-resistant hash function $H$;
- The signature becomes $(s_1, s_2, r)$, where $s_1$ and $s_2$ are in compressed format,
- The verifier accepts the signatures if and only if:
  - $(s_1, s_2)$ is short;
  - $pk==H(s_2^{-1}(HashToPoint(r\mid\mid m)-s_1))$

Note: In the context of ETHEREUM, It is valuable to stick to the `ecrecover` specification. 


### Falcon-Solidity: an EVM-friendly signature

**Tetration implementation.**
FALCON-SOLIDITY refers to the specification of [Tetration](https://github.com/Tetration-Lab/falcon-solidity/blob/main/src/Falcon.sol) repository. It is important to notice that this implementation is EVM friendly and use a FALCON equivalent implementation using a Keccak XOF instead of SHAKE. It is thus not compliant with [FALCON](https://falcon-sign.info/falcon.pdf) NIST instantiation. While assumingly not degrading the  security it is not compatible with the original specification.

**Optimizations.**
The performance improvement brought by ZKNOX to this version comes from :
-  generic solidity gas cost optimizations (replacing mul by shifts, etc.)
- the replacement of a recursive NTT, by a NWC (Negative Wrap Convolution) specialized one as specified in EIP-NTT following [LN16]. This NTT is twice faster and does not need to store a table of $q$ elements
- the precomputation of the NTT from of the public key to avoid repetitive identical computations for each iteration.


**Uncovered vulnerabilities on Tetration [v1.0](https://github.com/Tetration-Lab/falcon-solidity/blob/main/src/Falcon.sol).**


| Label                   | Severity | Description               |  Impact |Fix | PR |
|------------------------|---------------------|---------------------|---------------------|---------------------|---------------------|
|CVETH-2025-080201| critical  | salt size is not checked in verification | forge | add salt size checking | [here](https://github.com/Tetration-Lab/falcon-solidity/pull/1)
|CVETH-2025-080202| medium | signature malleability on coefficient signs | malleability | force positive coefficients in s part | [here](https://github.com/Tetration-Lab/falcon-solidity/pull/1)
|CVETH-2025-080203| low | no domain separation of internal state input and output | XOF design infringment | modify FALCON-SOLIDITY XOF specification | TBD


### Epervier: a compact EVM-friendly Falcon with public key recovery mode

**Optimization of FalconRec.**

In order to optimize the verification of FalconRec, we use a classical trick in ZK implementations by providing $s_2^{-1}$ as an extra value (a hint) in the calldata, in the NTT domain (i.e. we provide `ntt(s2Inverse)`). Then, the verifier needs to check that the hint is indeed the inverse of $s_2$:
- The public key remains $pk = H(h)$ for some collision-resistant hash function $H$;
- The signature becomes $σ  =(s_1,s_2,r,ntt(s_2^{-1}))$,
- The verification splits as:
  - $ntt(σ_2)\cdot σ_4 == ntt(1)$,
  - $(σ_1,σ_2)$ is short,
  - $pk==H(intt(σ_4\cdot ntt(HashToPoint(σ_3\mid\mid m)-σ_1)))$.

Finally, the cost of FalconRec verification is dominated by **2NTT + 1iNTT** (1 NTT in step 1, and the rest in step 3).

Note that the check of step one is done in the NTT domain, where $ntt(1)$ is the constant equal to 1 at every poition. It is a simple equality test once $ntt(σ_2)$ is computed.

**Moving the public key in the NTT domain.**

We present here a modification of the public key in order to reduce the verification cost. The public key is moved in the NTT domain in order to save an iNTT in the FalconRec verification. Epervier is summarized as follows:
- Public key: $pk=H(ntt(h))$ for some collision-resistant hash function $H$;
- Signature: $σ = (s_1, s_2, r, ntt(s_2^{-1}))$ 
- The verifier accepts the signatures if and only if:
    - $ntt(σ_2)\cdot σ_4==ntt(1)$;
    - $(σ_1,σ_2)$ is short;
    - $pk==H(σ_4\cdot (ntt(HashToPoint(r\mid\mid m)-σ_1)))$.

Using this verification, we compute only **2NTT** (+ additional hash computations and vectorized arithmetic) for the verification. This matches with the number of NTT in Falcon (without the recovery mode).

We claim that the interest of EPERVIER goes beyond Ethereum ecosystem. For hardware implementations, avoiding a NTTINV reduces the total required gates. Using a pipeline, it also enables to reuse the same NTT circuit inducing only latency of one stage of the implementation.

<!-- 
- the NTT used here is the NWC defined in NTT-EIP
- PRNG_Keccak is a construction that generates the desired output only using keccak (EVM friendly) 
- Defining H as H=ntt(keccak(c) remove to use Inverse NTT, this reduces the surface of hardware implementation. -->



### The Keccak-CTR PRNG

<img width="2200" height="1626" alt="image" src="https://github.com/user-attachments/assets/108d9bdb-02c7-4ab1-be54-46bd3ed2f534" />

The keccak-CTR PRNG is a minimalistic keccak in CTR mode, where:
- the state is initialized has keccak(message,salt)
- the i-th output block is keccak(state,i), where i is encoding on 1 byte
- each 16-bit chunk output is taken from MSB to LSB in the output chain, with rejection of each chunk greater or equal to 61445.
- if lesser than 61445, the chunk is reduced modulo q (12289)
