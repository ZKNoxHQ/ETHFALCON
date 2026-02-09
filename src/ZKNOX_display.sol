// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_display.sol
// Description: verify falcon core component
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {console} from "forge-std/Test.sol";

function Display_HexArray(string memory comment, uint256[] memory T) pure {
    console.log(comment);
    for (uint256 i = 0; i < T.length; i++) {
        console.log("%d %x", i, T[i]);
    }
}
