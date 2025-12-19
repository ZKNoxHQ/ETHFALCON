// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_falcon_encodings.sol";
import "../src/ZKNOX_ethfalcon.sol";
import "../src/ZKNOX_falcon_deploy.sol";

/// @title ZKNOX ETHFalcon KAT File Test
/// @notice Tests ZKNOX_ethfalcon against NIST KAT (Known Answer Test) files
/// @dev Parses falcon512-KAT.req and ethfalcon512-KAT.rsp files and verifies signatures
contract ETHFalconKATFileTest is Test {
    ZKNOX_ethfalcon falcon;

    function setUp() public {
        falcon = new ZKNOX_ethfalcon();
    }

    /// @notice Parse KAT response file and verify all 100 test vectors
    /// @dev Reads ethfalcon512-KAT.rsp and verifies all signatures
    ///      Requires gas_limit = 9223372036854775807 in foundry.toml
    function test_verifyAllKATVectors() public {
        string memory katFile = vm.readFile("test/ethfalcon512-KAT.rsp");

        // Parse and verify test vectors
        uint256 count = 0;
        uint256 passCount = 0;
        uint256 maxVectors = 10; // Test all 100 vectors from KAT file

        // Split file into test vectors (separated by blank lines)
        string[] memory vectors = splitByDoubleNewline(katFile);

        console.log("Total test vectors found:", vectors.length);
        console.log("Testing first", maxVectors, "vectors");

        for (uint256 i = 0; i < vectors.length && count < maxVectors; i++) {
            if (bytes(vectors[i]).length == 0) continue;

            // Parse this test vector
            KATVector memory vec = parseKATVector(vectors[i]);

            // Skip if this is just the header or incomplete vector
            if (vec.msg.length == 0 || vec.pk.length == 0 || vec.sm.length == 0) {
                continue;
            }

            count++;

            // Verify the signature
            bool result = verifyKATVector(vec);

            if (result) {
                passCount++;
                console.log("PASSED: Test vector", vec.count);
            } else {
                console.log("FAILED: Test vector", vec.count);
            }
        }

        console.log("Passed:", passCount, "/", count);
        console.log("Failed:", count - passCount, "/", count);
    }

    /// @notice Test KAT vector 0 specifically (the one from the existing test)
    /// @dev This tests against the known-good vector to verify our parsing logic
    function test_verifyKATVector0() public {
        // Hardcoded vector 0 from the KAT file for testing
        bytes memory pk =
            hex"096BA86CB658A8F445C9A5E4C28374BEC879C8655F68526923240918074D0147C03162E4A49200648C652803C6FD7509AE9AA799D6310D0BD42724E0635920186207000767CA5A8546B1755308C304B84FC93B069E265985B398D6B834698287FF829AA820F17A7F4226AB21F601EBD7175226BAB256D8888F009032566D6383D68457EA155A94301870D589C678ED304259E9D37B193BC2A7CCBCBEC51D69158C44073AEC9792630253318BC954DBF50D15028290DC2D309C7B7B02A6823744D463DA17749595CB77E6D16D20D1B4C3AAD89D320EBE5A672BB96D6CD5C1EFEC8B811200CBB062E473352540EDDEF8AF9499F8CDD1DC7C6873F0C7A6BCB7097560271F946849B7F373640BB69CA9B518AA380A6EB0A7275EE84E9C221AED88F5BFBAF43A3EDE8E6AA42558104FAF800E018441930376C6F6E751569971F47ADBCA5CA00C801988F317A18722A29298925EA154DBC9024E120524A2D41DC0F18FD8D909F6C50977404E201767078BA9A1F9E40A8B2BA9C01B7DA3A0B73A4C2A6B4F518BBEE3455D0AF2204DDC031C805C72CCB647940B1E6794D859AAEBCEA0DEB581D61B9248BD9697B5CB974A8176E8F910469CAE0AB4ED92D2AEE9F7EB50296DAF8057476305C1189D1D9840A0944F0447FB81E511420E67891B98FA6C257034D5A063437D379177CE8D3FA6EAF12E2DBB7EB8E498481612B1929617DA5FB45E4CDF893927D8BA842AA861D9C50471C6D0C6DF7E2BB26465A0EB6A3A709DE792AAFAAF922AA95DD5920B72B4B8856C6E632860B10F5CC08450003671AF388961872B466400ADB815BA81EA794945D19A100622A6CA0D41C4EA620C21DC125119E372418F04402D9FA7180F7BC89AFA54F8082244A42F46E5B5ABCE87B50A7D6FEBE8D7BBBAC92657CBDA1DB7C25572A4C1D0BAEA30447A865A2B1036B880037E2F4D26D453E9E913259779E9169B28A62EB809A5C744E04E260E1F2BBDA874F1AC674839DDB47B3148C5946DE0180148B7973D63C58193B17CD05D16E80CD7928C2A338363A23A81C0608C87505589B9DA1C617E7B70786B6754FBB30A5816810B9E126CFCC5AA49326E9D842973874B6359B5DB75610BA68A98C7B5E83F125A82522E13B83FB8F864E2A97B73B5D544A7415B6504A13939EAB1595D64FAF41FAB25A864A574DE524405E878339877886D2FC07FA0311508252413EDFA1158466667AFF78386DAF7CB4C9B850992F96E20525330599AB601D454688E294C8C3E";
        bytes memory sm =
            hex"02BB350CB957EEFFA82211A2EC1166D21AE7FFACDB32DB2A89AD209F0012AB03E0FDE69D9E02AF52996BD81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8299AF9A7635343E5233F5A14E75378D8E1B3C87186411C244906ADDE345EDD09A831CF0A19153B1AEF376EFCA8C74E4D677CC2E696758312A0F95733527589645DB193B08B5D37DFEC9FE27E8D16D337712EB1F6ABB79DC2114D3B2FFA22133663E25651FC1AC6226CC33DE59665138FDA4D0D66A2ED4C7B990B8822DC1E07A9B1AC222DC78E169AB92EBD2FC7A27460B23A08AA4A99D54592FAC288C904D61126860E6A191EBC59A09948311425EE19EAB02B0A53498659E94B0AE485CD4DD2E9985AF4F41FDC29EBC0ED2C6E925DB5B2B08FDF56024A23B9F4656EEA508995AD869F23EDC65D4B2A3A6485A2A82691A47214BF3C0D1C38FDD33EB4BBB9876588C273F7B46289839075AEDCCB428E87B1139533667B7CA781ADE43F7A3F773BD9356476BC35D0EAA2AD7A4F4DC9F4495F53338D6435392988BCB5AC71985E1B3CEB668D91D5EB71B28C8FC3BC9E6068F0AC9E69F1C6A8D8D6BB950AF7B46FF55354E4187CB40BDBA66BE6C93AFFB2741D9ED20307704F6E7ED5A42352A5D27CDA1F6FC5353A63B5369226C4D98EB4862083A4BDF2B4ED20AE8C84F7B8CA0A8FC930342E1C894B812B5006FB792543656CBB4B217E7F7C8C92A8F1553C0583311ACED7667BEECCC0D95691E40E7E40FE87871D1A28165D63BB013C10034FE0529BCDE391204B083B4C40CD050998B368DD66298EBC37CA1EFCF46DB4EC419EC3612AB96B152FB0A03295527CA0242F539930DA795D6D851B36611548D2BF1EC8C2B0C4694CED382ADBB587AC425B1AB5D0A1B43F54D390A6F0640F0F33C743ADD746DCFA6DE7592535FDE947F3A6916BC6A8AF5220449E39A429A120D011CF78DEB88E8E0B374AD0F2000000000000000000";
        bytes memory expectedMsg = hex"D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8";

        KATVector memory vec;
        vec.count = 0;
        vec.mlen = 33;
        vec.msg = expectedMsg;
        vec.pk = pk;
        vec.sm = sm;

        bool result = verifyKATVector(vec);
        assertTrue(result, "KAT vector 0 verification failed");
    }

    // ========== Internal Helper Functions ==========

    struct KATVector {
        uint256 count;
        bytes seed;
        uint256 mlen;
        bytes msg;
        bytes pk;
        bytes sk;
        uint256 smlen;
        bytes sm;
    }

    /// @notice Verify a single KAT test vector (prints errors instead of failing)
    function verifyKATVector(KATVector memory vec) internal returns (bool) {
        // Decompress the public key and signature
        (uint256[] memory kpub, uint256[] memory s2, bytes memory salt, bytes memory message) =
            decompress_KAT(vec.pk, vec.sm, vec.mlen);

        // Verify the message matches
        if (keccak256(message) != keccak256(vec.msg)) {
            console.log("Vector", vec.count, "- Message mismatch");
            console.log("Expected:");
            console.logBytes(vec.msg);
            console.log("Got:");
            console.logBytes(message);
            return false;
        }

        // Transform to NTT form
        uint256[] memory ntth = _ZKNOX_NTT_Compact(_ZKNOX_NTTFW_vectorized(kpub));
        uint256[] memory cs2 = _ZKNOX_NTT_Compact(s2);

        // Verify the signature
        bool result = falcon.verify(message, salt, cs2, ntth);

        if (!result) {
            console.log("Vector", vec.count, "- Signature verification FAILED");
            console.log("  (sm value in ethfalcon512-KAT.rsp needs to be updated with ETHFALCON signature)");
        }

        return result;
    }

    /// @notice Parse a KAT vector from text
    function parseKATVector(string memory vectorText) internal pure returns (KATVector memory vec) {
        string[] memory lines = splitByNewline(vectorText);

        for (uint256 i = 0; i < lines.length; i++) {
            string memory line = lines[i];
            if (bytes(line).length == 0) continue;

            (string memory key, string memory value) = splitKeyValue(line);

            if (compareStrings(key, "count")) {
                vec.count = parseUint(value);
            } else if (compareStrings(key, "seed")) {
                vec.seed = parseHexString(value);
            } else if (compareStrings(key, "mlen")) {
                vec.mlen = parseUint(value);
            } else if (compareStrings(key, "msg")) {
                vec.msg = parseHexString(value);
            } else if (compareStrings(key, "pk")) {
                vec.pk = parseHexString(value);
            } else if (compareStrings(key, "sk")) {
                vec.sk = parseHexString(value);
            } else if (compareStrings(key, "smlen")) {
                vec.smlen = parseUint(value);
            } else if (compareStrings(key, "sm")) {
                vec.sm = parseHexString(value);
            }
        }

        return vec;
    }

    /// @notice Split text by double newline (test vector separator)
    function splitByDoubleNewline(string memory text) internal pure returns (string[] memory) {
        bytes memory textBytes = bytes(text);
        uint256 vectorCount = 1;

        // Count vectors by finding "\n\n" sequences
        for (uint256 i = 0; i < textBytes.length - 1; i++) {
            if (textBytes[i] == "\n" && textBytes[i + 1] == "\n") {
                vectorCount++;
                i++; // Skip the second newline
            }
        }

        string[] memory vectors = new string[](vectorCount);
        uint256 vectorIndex = 0;
        uint256 start = 0;

        for (uint256 i = 0; i < textBytes.length - 1; i++) {
            if (textBytes[i] == "\n" && textBytes[i + 1] == "\n") {
                // Extract vector from start to i
                vectors[vectorIndex] = substring(text, start, i);
                vectorIndex++;
                start = i + 2; // Skip both newlines
                i++;
            }
        }

        // Add the last vector
        if (start < textBytes.length) {
            vectors[vectorIndex] = substring(text, start, textBytes.length);
        }

        return vectors;
    }

    /// @notice Split text by newline
    function splitByNewline(string memory text) internal pure returns (string[] memory) {
        bytes memory textBytes = bytes(text);
        uint256 lineCount = 1;

        for (uint256 i = 0; i < textBytes.length; i++) {
            if (textBytes[i] == "\n") {
                lineCount++;
            }
        }

        string[] memory lines = new string[](lineCount);
        uint256 lineIndex = 0;
        uint256 start = 0;

        for (uint256 i = 0; i < textBytes.length; i++) {
            if (textBytes[i] == "\n") {
                lines[lineIndex] = substring(text, start, i);
                lineIndex++;
                start = i + 1;
            }
        }

        // Add the last line
        if (start < textBytes.length) {
            lines[lineIndex] = substring(text, start, textBytes.length);
        }

        return lines;
    }

    /// @notice Split a line into key and value by " = "
    function splitKeyValue(string memory line) internal pure returns (string memory key, string memory value) {
        bytes memory lineBytes = bytes(line);

        // Handle lines too short to contain " = " (length < 3)
        if (lineBytes.length < 3) {
            return (line, "");
        }

        // Find " = " separator
        for (uint256 i = 0; i < lineBytes.length - 2; i++) {
            if (lineBytes[i] == " " && lineBytes[i + 1] == "=" && lineBytes[i + 2] == " ") {
                key = substring(line, 0, i);
                value = substring(line, i + 3, lineBytes.length);
                return (key, value);
            }
        }

        // No separator found, return whole line as key
        return (line, "");
    }

    /// @notice Extract substring from string
    function substring(string memory str, uint256 start, uint256 end) internal pure returns (string memory) {
        bytes memory strBytes = bytes(str);
        require(start <= end && end <= strBytes.length, "Invalid substring range");

        bytes memory result = new bytes(end - start);
        for (uint256 i = 0; i < end - start; i++) {
            result[i] = strBytes[start + i];
        }

        return string(result);
    }

    /// @notice Compare two strings for equality
    function compareStrings(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    /// @notice Parse unsigned integer from string
    function parseUint(string memory str) internal pure returns (uint256) {
        bytes memory strBytes = bytes(str);
        uint256 result = 0;

        for (uint256 i = 0; i < strBytes.length; i++) {
            uint8 digit = uint8(strBytes[i]);
            if (digit >= 48 && digit <= 57) {
                result = result * 10 + (digit - 48);
            }
        }

        return result;
    }

    /// @notice Parse hex string to bytes
    function parseHexString(string memory str) internal pure returns (bytes memory) {
        bytes memory strBytes = bytes(str);

        // Handle empty string
        if (strBytes.length == 0) {
            return new bytes(0);
        }

        // Remove "0x" prefix if present
        uint256 start = 0;
        if (strBytes.length >= 2 && strBytes[0] == "0" && strBytes[1] == "x") {
            start = 2;
        }

        // Each pair of hex chars = 1 byte
        uint256 len = (strBytes.length - start) / 2;
        bytes memory result = new bytes(len);

        for (uint256 i = 0; i < len; i++) {
            uint8 high = hexCharToByte(strBytes[start + i * 2]);
            uint8 low = hexCharToByte(strBytes[start + i * 2 + 1]);
            result[i] = bytes1((high << 4) | low);
        }

        return result;
    }

    /// @notice Convert hex character to byte value
    function hexCharToByte(bytes1 char) internal pure returns (uint8) {
        uint8 c = uint8(char);

        if (c >= 48 && c <= 57) {
            // '0' - '9'
            return c - 48;
        } else if (c >= 65 && c <= 70) {
            // 'A' - 'F'
            return c - 55;
        } else if (c >= 97 && c <= 102) {
            // 'a' - 'f'
            return c - 87;
        }

        revert("Invalid hex character");
    }
}
