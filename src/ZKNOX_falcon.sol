// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_falcon.sol
// Description: verify falcon core component
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_common.sol";
import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_falcon_core.sol";
import "./ZKNOX_HashToPoint.sol";
import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";
import {SSTORE2} from "sstore2/SSTORE2.sol";

/// @title ZKNOX_falcon
/// @notice A contract to verify FALCON signatures
/// @dev The format of function is compacted, not compressed. For NIST KAT verification see test/falconKATS.t.sol and test/falcon_KAT_file.t.sol.

/// @custom:experimental This library is not audited yet, do not use in production.

contract ZKNOX_falcon is ISigVerifier {
    struct CompactSignature {
        bytes salt;
        uint256[] s2; // compacted signature
    }

    function CheckParameters(CompactSignature memory signature, uint256[] memory ntth) internal pure returns (bool) {
        if (ntth.length != falcon_S256) return false; //"Invalid public key length"
        if (signature.salt.length != 40) return false; //CVETH-2025-080201: control salt length to avoid potential forge
        if (signature.s2.length != falcon_S256) return false; //"Invalid salt length"

        return true;
    }

    /// @notice Stores a public key in an SSTORE2 data contract and returns its ERC-7913 key bytes
    /// @dev Permissionless: anyone can write any valid key. The returned 20-byte pointer is the key
    ///      identifier used by `verify(bytes,bytes32,bytes)`, so the account must store it itself; a key
    ///      is only as trusted as the pointer the account stores. The same ntth can sit behind several
    ///      pointers: deduplicate on keccak256(ntth) if key uniqueness matters.
    /// @param pubkey abi.encode(uint256[] ntth), ntth being the public key in the NTT domain, compacted
    ///        (32 words of 16 coefficients of 16 bits), each coefficient < q. Reverts otherwise.
    /// @return the 20-byte address of the SSTORE2 pointer (abi.encodePacked(address))
    function setKey(bytes memory pubkey) external returns (bytes memory) {
        if (!falcon_checkKeyEncoding(pubkey)) revert("invalid public key");
        address pointer = SSTORE2.write(pubkey);
        return abi.encodePacked(pointer);
    }

    /// @notice Compute the falcon NIST (SHAKE256 hash-to-point) verification function
    /// @dev Reverts on malformed lengths (salt, s2, ntth); returns false on an invalid signature or on a
    ///      public key with a coefficient >= q. No domain (chainId, contract, nonce) is bound by the
    ///      verifier: callers must include it in the signed message.
    /// @param h the message, raw bytes of any length (it is hashed together with the salt by the hash-to-point)
    /// @param salt the signature salt (nonce), expected length is 40 bytes
    /// @param s2 second part of the signature in Compacted representation (see IO part of README for encodings specification), expected length is 32 uint256
    /// @param ntth public key in the ntt domain, compacted 16 coefficients of 16 bits per word, each coefficient < q
    /// @return result boolean result of the verification
    function verify(
        bytes memory h, // the message, any length
        bytes memory salt, // compacted signature salt part
        uint256[] memory s2, // compacted signature s2 part
        uint256[] memory ntth // public key, compacted representing coefficients over 16 bits
    )
        external
        pure
        returns (bool result)
    {
        return _verify(h, salt, s2, ntth);
    }

    /// @notice ERC-7913 verification entry point
    /// @dev Reverts if `_pubkey` is not exactly the 20-byte address of a valid `setKey` pointer, or if `_sig`
    ///      is not exactly salt (40 bytes) || s2 (32 words). Returns 0xFFFFFFFF on an invalid signature.
    /// @param _pubkey 20-byte address of the SSTORE2 pointer returned by `setKey`
    /// @param _digest the 32-byte message that was signed
    /// @param _sig salt (40 bytes) || s2 (32 uint256 words, compacted)
    /// @return ISigVerifier.verify.selector if the signature is valid, 0xFFFFFFFF otherwise
    function verify(bytes calldata _pubkey, bytes32 _digest, bytes calldata _sig) external view returns (bytes4) {
        //enforce the canonical encoding: salt (40 bytes) || s2 (32 words of 32 bytes).
        //floor division would otherwise accept 1 to 31 trailing garbage bytes,
        //yielding up to 32 distinct accepted encodings of the same signature.
        if (_sig.length != SALT_LEN + 32 * falcon_S256) {
            revert("invalid signature length");
        }

        uint256[] memory ntth = falcon_loadKeyPointer(_pubkey);

        bytes memory salt = _sig[:SALT_LEN];
        uint256[] memory s2 = new uint256[](falcon_S256);
        assembly ("memory-safe") {
            calldatacopy(add(s2, 32), add(_sig.offset, SALT_LEN), mul(32, falcon_S256))
        }

        if (_verify(abi.encodePacked(_digest), salt, s2, ntth)) {
            return ISigVerifier.verify.selector;
        }
        return 0xFFFFFFFF;
    }

    function _verify(bytes memory h, bytes memory salt, uint256[] memory s2, uint256[] memory ntth)
        internal
        pure
        returns (bool)
    {
        if (salt.length != SALT_LEN) {
            revert("invalid salt length");
        } //CVETH-2025-080201: control salt length to avoid potential forge
        if (s2.length != falcon_S256) {
            revert("invalid s2 length");
        }
        if (ntth.length != falcon_S256) {
            revert("invalid ntth length");
        }

        uint256[] memory hashed = hashToPointNIST(salt, h);

        return falcon_core(s2, ntth, hashed);
    }
} //end of contract ZKNOX_falcon_compact
