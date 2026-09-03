// SPDX-License-Identifier: MIT
// FILE: ZKNOX_falcon_core_packed.sol
// falcon_core on the packed-SWAR NTT. Same result as falcon_core, asserted
// against it. Two differences beyond the NTT itself:
//   - the public key is consumed straight from its compact form, so the two
//     Expand(32 -> 512) calls disappear;
//   - the Compact(512 -> 32) then Expand(32 -> 512) round trip that falcon_core
//     performs on s1 (an identity for coefficients < 2^16, which NTTINV output
//     always is) is gone.
// falcon_normalize is untouched and still takes s1 expanded.
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_falcon_core.sol";
import "./ZKNOX_NTT_falcon_packed.sol";

function falcon_core_packed(uint256[] memory s2, uint256[] memory ntth, uint256[] memory hashed)
    pure
    returns (bool)
{
    if (hashed.length != 512) return false;
    if (s2.length != 32) return false;
    if (ntth.length != 32) return false;

    uint256[] memory s1 =
        _unpackTo512(_nttInvPacked(_vecMulPacked(_nttFwPacked(_packFromCompact(s2)), _packFromCompact(ntth))));

    return falcon_normalize(s1, s2, hashed);
}
