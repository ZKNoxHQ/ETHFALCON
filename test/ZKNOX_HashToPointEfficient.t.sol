// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
// import "../src/HashToPointEfficient_ZKNOX.sol";
// import {ZKNOX_HashToPoint} from "../src/ZKNOX_HashToPoint.sol";
import "../src/Tetration_HashToPoint.sol";

contract HashToPointZKNOXTest is Test {
// function test_H2P_Zhenfei() public {
//     ZKNOX_HashToPoint H2P = new ZKNOX_HashToPoint();

//     bytes memory salt =
//         "5\x001\x8fu\xad \xf0\xaa b\xba\x1c4\x8a\xfe\xaaI#\x87\xa4c\xeb\x8c(\xafw\x9dj>\xa6\x96\xeb\xb9f\x0c\xcf\xf5\x06-";
//     bytes memory msgHash = "My name is Renaud";
//     uint256 q = 12289;
//     uint256 n = 512;
//     uint256[] memory hash_efficient = hashToPointEfficient(salt, msgHash, q, n);
//     uint256[] memory hash = H2P.hashToPoint(salt, msgHash, q, n);
//     assertEq(hash, hash_efficient);
//     // obtained from python
//     // assertEq(hash[0], 2918);
//     // assertEq(hash[1], 6850);
//     // assertEq(hash[2], 8308);
//     // assertEq(hash[3], 8464);
//     // assertEq(hash[4], 5824);
// }

// function test_H2P1() public {
//     ZKNOX_HashToPoint H2P = new ZKNOX_HashToPoint();
//     bytes memory salt =
//         "5\x001\x8fu\xad \xf0\xaa b\xba\x1c4\x8a\xfe\xaaI#\x87\xa4c\xeb\x8c(\xafw\x9dj>\xa6\x96\xeb\xb9f\x0c\xcf\xf5\x06-";
//     bytes memory msgHash = "My name is Renaud";
//     uint256 q = 12289;
//     uint256 n = 512;
//     uint256[] memory hash = H2P.hashToPoint(salt, msgHash, q, n);
// }

// function test_H2P2() public {
//     bytes memory salt =
//         "5\x001\x8fu\xad \xf0\xaa b\xba\x1c4\x8a\xfe\xaaI#\x87\xa4c\xeb\x8c(\xafw\x9dj>\xa6\x96\xeb\xb9f\x0c\xcf\xf5\x06-";
//     bytes memory msgHash = "My name is Renaud";
//     uint256 q = 12289;
//     uint256 n = 512;
//     uint256[] memory hash_efficient = hashToPointEfficient(salt, msgHash, q, n);
// }

// function test_H2P3() public {
//     bytes memory salt =
//         "5\x001\x8fu\xad \xf0\xaa b\xba\x1c4\x8a\xfe\xaaI#\x87\xa4c\xeb\x8c(\xafw\x9dj>\xa6\x96\xeb\xb9f\x0c\xcf\xf5\x06-";
//     bytes memory msgHash = "My name is Renaud";
//     uint256 q = 12289;
//     uint256 n = 512;
//     uint256[] memory hash_efficient = hashToPoint(salt, msgHash, q, n);
// }
}
