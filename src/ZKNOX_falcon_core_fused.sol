// SPDX-License-Identifier: MIT
// FILE: ZKNOX_falcon_core_fused.sol
// falcon_core on the fused radix-8 NTT (ZKNOX_NTT_falcon_fused.sol). Same
// accept/reject decision as falcon_core, asserted against it in
// test/falcon_fused.t.sol. Differences from falcon_core_packed:
//   - s2 goes straight from its compact form into the first forward pass (the
//     spread is folded into the loads), and the public key is multiplied in
//     from its compact form inside the first inverse pass: no _packFromCompact,
//     no _vecMulPacked, no _unpackTo512;
//   - the inverse transform returns s1 canonical (< q), in the packed layout;
//   - the two halves of falcon_normalize become _s2NormCompact (range check
//     and ||s2||^2 on the 32 compact words) and _normS1Packed (||h - s1||^2 on
//     the 128 packed words), so nothing is ever expanded to one coefficient per
//     word. The hash-to-point output must be packed as well (hashToPointNISTPacked).
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_NTT_falcon_fused.sol";

/// @param s2 compact signature polynomial, 16 coefficients of 16 bits per word
/// @param ntth compact public key, NTT domain, 16 coefficients of 16 bits per word
/// @param hashedPacked hashToPointNISTPacked output, 4 coefficients of 64 bits per word
function falcon_core_fused(uint256[] memory s2, uint256[] memory ntth, uint256[] memory hashedPacked)
    pure
    returns (bool)
{
    if (hashedPacked.length != 128) return false;
    if (s2.length != 32) return false;
    if (ntth.length != 32) return false;

    // Range check first: a coefficient >= q is a malleable encoding (falcon_normalize
    // rejects it too), and the forward transform's spread assumes 15-bit fields.
    (uint256 outOfRange, uint256 norm) = _s2NormCompact(s2);
    if (outOfRange != 0) return false;

    uint256[] memory s1 = _nttInvFusedMul(_nttFwFused(s2), ntth);
    norm += _normS1Packed(hashedPacked, s1);

    // accept iff norm <= sigBound, matching the reference (reject only norm > sigBound)
    return norm <= sigBound;
}
