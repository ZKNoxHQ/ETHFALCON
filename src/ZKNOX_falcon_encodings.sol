// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_falcon_encodings.sol
// Description: decoding of NIST (round 3) compressed Falcon-512 signatures and KAT vectors (test helper)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";

uint256 constant max_in_len = 666;

/// @dev Length of a NIST Falcon-512 public key: header byte 0x09 || 512 coefficients of 14 bits
uint256 constant falcon_pk_nist_len = 897;

/// @notice Decodes a compressed Falcon-512 signature polynomial from buf[offset:end]
/// @dev Follows comp_decode of the NIST reference: never reads at or past `end`, rejects coefficients
///      above 2047, the "-0" encoding and non-zero unused bits in the last byte.
/// @param buf Buffer holding the compressed polynomial
/// @param offset Index of the first byte to decode
/// @param end Index past the last byte that may be read (<= buf.length)
/// @return x Decoded polynomial, 512 coefficients in [0, q)
/// @return v Index past the last byte consumed
function _decompress_sig_bounded(bytes memory buf, uint256 offset, uint256 end)
    pure
    returns (uint256[] memory x, uint256 v)
{
    if (end > buf.length || offset > end) revert("invalid bounds");
    x = new uint256[](512);
    v = offset;
    uint256 err = 0;

    assembly ("memory-safe") {
        let data := add(buf, 32)
        let xp := add(x, 32)
        let acc := 0
        let acc_len := 0
        for { let u := 0 } lt(u, 512) { u := add(u, 1) } {
            // get next eight bits: sign and low seven bits of the absolute value
            if iszero(lt(v, end)) {
                err := 1
                break
            }
            acc := or(shl(8, acc), byte(0, mload(add(data, v))))
            v := add(v, 1)
            let b := shr(acc_len, acc)
            let s := and(b, 128)
            let m := and(b, 127)

            // unary-encoded high bits
            for {} 1 {} {
                if iszero(acc_len) {
                    if iszero(lt(v, end)) {
                        err := 1
                        break
                    }
                    acc := or(shl(8, acc), byte(0, mload(add(data, v))))
                    v := add(v, 1)
                    acc_len := 8
                }
                acc_len := sub(acc_len, 1)
                if and(shr(acc_len, acc), 1) { break }
                m := add(m, 128)
                if gt(m, 2047) {
                    err := 2
                    break
                }
            }
            if err { break }

            // "-0" is forbidden
            if and(iszero(m), eq(s, 128)) {
                err := 3
                break
            }

            let val := m
            if s { val := sub(q, m) }
            mstore(add(xp, shl(5, u)), val)
        }
        // the unused bits of the last byte must be zero
        if iszero(err) { if and(acc, sub(shl(acc_len, 1), 1)) { err := 4 } }
    }

    if (err == 1) revert("truncated signature");
    if (err == 2) revert("coeff to big");
    if (err == 3) revert("incorrect zero encoding");
    if (err == 4) revert("non-zero padding");
    if ((v - offset) >= max_in_len) revert("too long");
}

/// @notice Decodes a compressed signature polynomial starting at `offset`, in the padded format
/// @dev The polynomial may be followed by zero bytes only (padded format); any other trailing byte reverts.
function _decompress_sig(bytes memory buf, uint256 offset) pure returns (uint256[] memory x) {
    uint256 v;
    (x, v) = _decompress_sig_bounded(buf, offset, buf.length);
    for (; v < buf.length; v++) {
        if (buf[v] != 0) revert("trailing bytes");
    }
}

/*
	 * Decode NIST KAT made of
     * the encoded public key:0x09+ public key compressed value
     * the signature bundled with the message. Format is:
	 *   signature length     slen encoded on 2 bytes, big-endian
	 *   nonce                40 bytes
	 *   message              mlen bytes
	 *   signature            slen bytes: header 0x29 || compressed s2
	 * The encoding is checked strictly as in the NIST reference crypto_sign_open: slen must match the
	 * actual length (no trailing bytes), the compressed s2 must use exactly slen - 1 bytes with zero
	 * padding bits and no "-0", and the public key must be exactly 897 bytes.
	 */
function decompress_KAT(bytes memory pk, bytes memory sm, uint256 mlen)
    pure
    returns (uint256[] memory h, uint256[] memory s2, bytes memory salt, bytes memory message)
{
    if (sm.length < 2) revert("invalid signature length");
    uint256 slen = (uint256(uint8(sm[0])) << 8) + uint256(uint8(sm[1]));
    if (slen == 0 || sm.length != 2 + 40 + mlen + slen) revert("invalid signature length");

    /*
    * Decode public key.
    */
    if (pk.length != falcon_pk_nist_len || pk[0] != 0x09) {
        revert("wrong public key encoding");
    }
    h = _ZKNOX_NTT_Decompress(pk, 1); //decompressing kpub, assuming first byte is 0x09, so offset=1

    uint256 i;
    salt = new bytes(40);

    for (i = 0; i < 40; i++) {
        salt[i] = sm[i + 2];
    }
    message = new bytes(mlen);
    for (uint256 j = 0; j < mlen; j++) {
        message[j] = sm[j + 42];
    }

    if (sm[2 + 40 + mlen] != 0x29) {
        revert("wrong header sigbytes");
    }

    uint256 v;
    (s2, v) = _decompress_sig_bounded(sm, 2 + 40 + mlen + 1, sm.length);
    if (v != sm.length) revert("trailing bytes");

    return (h, s2, salt, message);
}
