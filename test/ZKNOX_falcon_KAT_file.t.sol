// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_falcon_encodings.sol";
import "../src/ZKNOX_falcon.sol";
import "../src/ZKNOX_falcon_deploy.sol";

/// @title ZKNOX Falcon KAT File Test
/// @notice Tests ZKNOX_falcon against NIST KAT (Known Answer Test) files
/// @dev Parses falcon512-KAT.req and falcon512-KAT.rsp files and verifies signatures
contract FalconKATFileTest is Test {
    ZKNOX_falcon falcon;
    ZKNOX_NTT ntt = new ZKNOX_NTT(address(0), address(0), 12289, 12265);

    function setUp() public {
        bytes32 salt = keccak256(abi.encodePacked("ZKnox"));
        falcon = new ZKNOX_falcon();

        address a_psirev;
        address a_psiInvrev;
        (a_psirev, a_psiInvrev) = Deploy(salt);
        falcon.update(a_psirev, a_psiInvrev);
    }

    /// @notice Parse KAT response file and verify all 100 test vectors
    /// @dev Reads falcon512-KAT.rsp and verifies all signatures
    ///      Requires gas_limit = 9223372036854775807 in foundry.toml
    function test_verifyAllKATVectors() public {
        string memory katFile = vm.readFile("test/falcon512-KAT.rsp");

        // Parse and verify test vectors
        uint256 count = 0;
        uint256 passCount = 0;
        uint256 maxVectors = 100; // Test all 100 vectors from KAT file

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
        assertEq(passCount, count, "Some KAT vectors failed");
    }

    /// @notice Test KAT vector 0 specifically (the one from the existing test)
    /// @dev This tests against the known-good vector to verify our parsing logic
    function test_verifyKATVector0() public {
        // Hardcoded vector 0 from the KAT file for testing
        bytes memory pk = hex"096BA86CB658A8F445C9A5E4C28374BEC879C8655F68526923240918074D0147C03162E4A49200648C652803C6FD7509AE9AA799D6310D0BD42724E0635920186207000767CA5A8546B1755308C304B84FC93B069E265985B398D6B834698287FF829AA820F17A7F4226AB21F601EBD7175226BAB256D8888F009032566D6383D68457EA155A94301870D589C678ED304259E9D37B193BC2A7CCBCBEC51D69158C44073AEC9792630253318BC954DBF50D15028290DC2D309C7B7B02A6823744D463DA17749595CB77E6D16D20D1B4C3AAD89D320EBE5A672BB96D6CD5C1EFEC8B811200CBB062E473352540EDDEF8AF9499F8CDD1DC7C6873F0C7A6BCB7097560271F946849B7F373640BB69CA9B518AA380A6EB0A7275EE84E9C221AED88F5BFBAF43A3EDE8E6AA42558104FAF800E018441930376C6F6E751569971F47ADBCA5CA00C801988F317A18722A29298925EA154DBC9024E120524A2D41DC0F18FD8D909F6C50977404E201767078BA9A1F9E40A8B2BA9C01B7DA3A0B73A4C2A6B4F518BBEE3455D0AF2204DDC031C805C72CCB647940B1E6794D859AAEBCEA0DEB581D61B9248BD9697B5CB974A8176E8F910469CAE0AB4ED92D2AEE9F7EB50296DAF8057476305C1189D1D9840A0944F0447FB81E511420E67891B98FA6C257034D5A063437D379177CE8D3FA6EAF12E2DBB7EB8E498481612B1929617DA5FB45E4CDF893927D8BA842AA861D9C50471C6D0C6DF7E2BB26465A0EB6A3A709DE792AAFAAF922AA95DD5920B72B4B8856C6E632860B10F5CC08450003671AF388961872B466400ADB815BA81EA794945D19A100622A6CA0D41C4EA620C21DC125119E372418F04402D9FA7180F7BC89AFA54F8082244A42F46E5B5ABCE87B50A7D6FEBE8D7BBBAC92657CBDA1DB7C25572A4C1D0BAEA30447A865A2B1036B880037E2F4D26D453E9E913259779E9169B28A62EB809A5C744E04E260E1F2BBDA874F1AC674839DDB47B3148C5946DE0180148B7973D63C58193B17CD05D16E80CD7928C2A338363A23A81C0608C87505589B9DA1C617E7B70786B6754FBB30A5816810B9E126CFCC5AA49326E9D842973874B6359B5DB75610BA68A98C7B5E83F125A82522E13B83FB8F864E2A97B73B5D544A7415B6504A13939EAB1595D64FAF41FAB25A864A574DE524405E878339877886D2FC07FA0311508252413EDFA1158466667AFF78386DAF7CB4C9B850992F96E20525330599AB601D454688E294C8C3E";
        bytes memory sm = hex"026833B3C07507E4201748494D832B6EE2A6C93BFF9B0EE343B550D1F85A3D0DE0D704C6D17842951309D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8290765843D1E460D17A527D2BCA405BD55BBC7DA09A8C620BE0AF4A767D9DB96B80F55E466676751EAABA7B93B86D71132DAA0EB376782B9EEE37519CE10FDD33FE9F29312C31D8736206D165CF4C528AA3DDC017845E1F0DD5B0A44FF961C42D874A95533E5B438982F524CA954D87533BFBE42C63FF2ABC77A34C79DB55A99171BBCB72C842A6530AF2F753F0C34AC632F9F1E7949F0BF6C67665B27722A8857D626B6FF1A136D923A39F4069B7477FF946E5247A6627791D49B59EDC9E2525A860E6E9828D18F64A9F17222E8166A02453859BBDA0B8186D8C9928BB571E4146401D7430E225904673AD21CCAC54C146C248A1DD69AB6491E901D6D71B152155BE97DE057F3916A3F1B4273308C29B2F4D9697167B90681B1583ED930A71E990467DEA368134BECEEBD597F9BEC922E816F1B0570D728F4AE0464C1F797657F87A4E52DCDCAEB9272662EA66D7C6CD8781B31AF555AD93F5F65E75816CB8DC306BB67E592B5261BACA7C509629EA2AF8ABB80CBA89EE535B76DFD9CCBBE3BF48F2BC8AA34B26E1103291053F5CB8DE3A45AFA5A76DF8B2122ED2C82FBCF2259290D41A14F86B12F35F5D49762B34CFF13EE7E42EDEC70201D7F37C33316288FA3078E36E58108865C3CFE263D563692043DECC62F3426F86061285B7B1B336F56FF41BB65E9CD6D9B92FD90F864AA1C923CB8C755F5CDE1770D862595427149D7721AAAB5D194AEA9ACDECA15BE43CBA6A62B5A33909E9FC4DA1C5814FBD7CD6A2FA572E318B42C6C319140B86E66392580A11A2B431F44C1F9270E4F7B2490F3B325A9977A71A575915636635B9969DBD6D220B24C3D99CEBBBD834B88222BD08C3ABE124E80";
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

    /// @notice Verify a single KAT test vector
    function verifyKATVector(KATVector memory vec) internal view returns (bool) {
        // Decompress the public key and signature
        (uint256[] memory kpub, uint256[] memory s2, bytes memory salt, bytes memory message) =
            decompress_KAT(vec.pk, vec.sm, vec.mlen);

        // Verify the message matches
        if (keccak256(message) != keccak256(vec.msg)) {
            console.log("Message mismatch for vector", vec.count);
            return false;
        }

        // Transform to NTT form
        uint256[] memory ntth = _ZKNOX_NTT_Compact(_ZKNOX_NTTFW_vectorized(kpub));
        uint256[] memory cs2 = _ZKNOX_NTT_Compact(s2);

        // Verify the signature
        return falcon.verify(message, salt, cs2, ntth);
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