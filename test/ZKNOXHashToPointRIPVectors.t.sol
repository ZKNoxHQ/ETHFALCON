// code generated using pythonref/generate_hashtopoint_test_vectors.py.
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_HashToPoint.sol";

contract HashToPointTest is Test {
    function testVector0() public pure {
        bytes memory salt =
            "\x46\xb9\xdd\x2b\x0b\xa8\x8d\x13\x23\x3b\x3f\xeb\x74\x3e\xeb\x24\x3f\xcd\x52\xea\x62\xb8\x1b\x82\xb5\x0c\x27\x64\x6e\xd5\x76\x2f\xd7\x5d\xc4\xdd\xd8\xc0\xf2\x00";
        bytes memory message = "My name is Renaud";
        // forgefmt: disable-next-line
        uint256[512] memory expected_hash = [uint256(8744), 9952,7149,4779,11786,10889,6385,1181,7100,7189,6211,9671,4540,9318,11953,1642,163,6091,7337,12233,2308,6730,11657,10024,4668,8040,522,7560,1751,7358,9452,8746,4081,1964,5377,3603,8832,8956,5963,2931,1636,11116,6615,8391,3906,4363,2873,469,741,9050,6093,7641,9448,760,8049,3579,4449,6665,707,8739,7210,6144,6400,9583,11322,10865,3184,9394,5204,4446,9203,12221,4269,4511,2856,542,10980,5976,8725,4494,7236,606,8748,6885,3847,5265,12134,1342,586,6068,2517,2685,3859,11063,3037,8329,7684,2301,2448,4020,6467,5208,4311,5371,11962,7086,2161,1364,7638,9608,3282,2485,6626,8297,3352,2184,653,4908,7992,747,7239,7170,4951,5816,6302,2617,4355,11460,8697,11335,9182,414,9643,1262,1324,777,12252,8802,3154,8473,1799,9835,6632,1326,335,8502,11557,10977,12241,11287,3771,1990,5922,7096,2459,11720,2073,10315,9482,2976,7791,8922,389,5421,9424,7779,11708,8374,9190,4683,1468,10705,10061,6894,2495,2969,5433,7755,8738,5139,8753,899,7878,9330,3716,9238,2373,10743,5347,4269,10393,6420,8192,9920,5806,678,8580,7866,3167,8041,10067,3591,6448,11933,8092,6121,1304,355,2541,9902,9359,1082,319,4204,5858,9360,910,9706,8771,200,3467,5004,2727,3955,3106,7348,1759,12000,2117,3814,8576,11973,5817,8056,5785,6835,10702,6370,4749,7640,3096,3812,2176,2412,5478,3910,8172,2406,3353,11923,577,11977,11114,6867,6461,9854,1949,6407,157,11758,10869,11073,1835,11172,9325,8034,1171,5273,11536,3893,10672,2993,10065,2780,10722,11128,4184,2005,1010,9136,1775,11277,10086,5229,9254,11343,10670,7394,4803,1746,7000,5035,9416,8731,6927,3708,9385,5461,4657,10342,7922,2049,3149,8204,9505,3162,5866,11424,7460,6673,2047,496,11421,937,293,4547,4245,1466,502,4884,547,8861,736,2301,1648,6525,1267,433,11573,10747,8655,9819,10813,10201,6568,6783,8736,4716,10150,3265,3321,9072,6211,6548,6591,5060,7138,1021,11237,12186,2990,8874,11131,105,10261,1334,1474,2895,4934,3750,11274,1377,3722,7895,2622,3667,1731,9451,7796,6051,11398,8760,10524,8558,5268,5090,7487,405,8593,1566,11029,7566,11222,9849,1281,1969,3922,11378,1587,764,5758,7358,1810,8768,7423,6493,5977,9416,11683,6347,8425,9633,3867,7626,2991,10568,7824,4611,8887,6243,6190,11307,7404,9955,3056,8872,9046,4105,10924,2477,690,1660,591,9915,5886,7094,7512,255,3700,6563,9357,2294,2329,8367,7028,864,585,5516,3551,11616,4993,8600,11889,4702,10123,11272,10774,7193,240,2976,6827,100,11698,7533,9468,9821,145,5127,2938,3022,363,7564,8361,4516,7543,5526,6244,8388,4094,6995,12111,1559,6465,12012,3649,3934,3569,9600,4984,6529,10509,8774,3062,7583,1453,6875,8493,6259,1325,6814,8422,1454,8313,11265,12260,5766,10156,370,1265,8328,6336,10072,8685,6552,10494,12166,11621,5853,3015,12174,212,3581];
        uint256 q = 12289;
        uint256 n = 512;
        uint256[] memory hash = hashToPointRIP(salt, message);
        for (uint256 i = 0; i < n; i++) {
            assertEq(hash[i], expected_hash[i]);
        }
    }

    function testVector1() public pure {
        bytes memory salt =
            "\xcb\x05\x01\x9d\x67\xb5\x92\xf6\xfc\x82\x1c\x49\x47\x9a\xb4\x86\x40\x29\x2e\xac\xb3\xb7\xc4\xbe\x14\x1e\x96\x61\x6f\xb1\x39\x57\x69\x2c\xc7\xed\xd0\xb4\x5a\xe3";
        bytes memory message = "My name is Simon";
        // forgefmt: disable-next-line
        uint256[512] memory expected_hash = [uint256(8737), 7826,6051,10789,5245,775,6459,8034,7380,4592,11075,10493,8813,9864,10091,2217,6906,1259,2715,529,4857,3621,9239,3011,8981,8030,6309,4605,1480,11308,1342,11162,11994,11930,11718,8143,3846,5285,1141,9,1676,3080,9343,11306,9539,4155,4739,2213,7477,2525,10592,1037,10697,610,5850,7054,5967,8372,291,404,11372,8970,10396,10469,1447,2272,11474,8324,2485,6666,7796,6097,10118,12282,2391,2508,2832,2577,1502,3568,7444,5859,8811,1587,6276,11552,2917,5072,4719,2125,2974,10901,11657,11809,9299,11059,6315,4181,12261,322,8877,7708,6458,4307,12217,2551,8970,8529,10319,6191,638,6268,9375,12137,10385,10028,1277,10514,3794,11620,12113,3760,10608,5826,9771,7996,8342,9561,2048,6736,1002,2704,10607,7482,436,7813,9431,2711,8632,10724,8899,662,8288,74,4667,1086,10288,2985,11113,8239,9280,7855,7319,671,6484,7517,4588,5318,5831,989,128,5020,1094,11918,8593,4075,6195,2565,7782,3377,4342,1643,7189,728,9514,1540,10799,11464,2986,7328,11177,8136,4955,3062,6055,6279,2274,7836,1901,9106,10594,6882,9615,9609,11999,11396,7188,671,1845,1069,1049,10982,7543,6193,3730,1284,4609,1282,1336,3709,12158,8880,9243,7927,39,2818,2478,1290,3762,9135,7413,8699,3758,3595,1721,4794,4788,9533,3863,6402,10775,3212,8542,4847,8097,11820,7111,10549,3471,367,58,10565,5979,8768,1222,871,6497,11000,9522,816,6752,1095,1581,10468,8431,6229,407,3586,4306,4503,3141,4792,9093,12216,8292,379,10447,1006,9384,2151,10224,1435,11076,8343,10756,11815,9978,7165,1135,4501,9080,9520,8536,5699,5116,9118,11391,6532,4481,9536,6311,5357,5408,9522,5407,9515,8585,8180,695,10886,5634,4119,10722,7746,353,8713,7397,9665,9672,12019,6657,8297,5019,1084,5722,6131,7291,5529,3797,7319,5873,6688,362,9198,4059,4902,9545,727,6141,10499,10594,414,407,3081,7636,4395,5739,4448,6451,11828,157,8300,8367,6263,2003,1101,11987,5177,1661,6913,7939,4253,7998,4551,6252,6928,10080,1359,8163,10714,11212,5247,5119,1942,7928,9546,2833,10827,6058,2143,6243,1219,7147,5079,1093,2534,8899,3592,4136,6781,2737,5011,7317,9533,11254,408,4480,8682,3549,4521,4431,4644,11913,8769,11151,10862,4604,7075,1951,1002,6136,2352,4496,9403,1655,5032,3713,875,8822,6940,9332,11773,7662,3146,10649,4388,3026,8269,3358,12075,9354,9818,5421,438,7968,4698,1844,3591,11097,1094,1920,3168,695,1281,5243,11634,2913,6651,2171,12162,7068,11702,1224,9597,5198,1158,1842,9222,7095,10586,309,9444,4651,2339,5622,12173,6476,11919,10154,9487,8480,1223,6570,9725,9734,2005,11573,3139,8097,3937,4016,7859,3027,1356,1743,2494,6546,1516,12175,8532,5106,4545,529,6025,7402,8339,6567,9881,7192,2475,7370,7009,9731,491,4686,10450,2984,11582,11852,7076,6740,12280,8945,7058,7048,6589,2636,6984,7317,5009,6278,3824];
        uint256 q = 12289;
        uint256 n = 512;
        uint256[] memory hash = hashToPointRIP(salt, message);
        for (uint256 i = 0; i < n; i++) {
            assertEq(hash[i], expected_hash[i]);
        }
    }

    function testVector2() public pure {
        bytes memory salt =
            "\xdc\x07\x22\x3c\x8e\x92\x93\x7b\xef\x84\xbc\x0e\xab\x86\x28\x53\x34\x9e\xc7\x55\x46\xf5\x8f\xb7\xc2\x77\x5c\x38\x46\x2c\x50\x10\xd8\x46\xc1\x85\xc1\x51\x11\xe5";
        bytes memory message = "My name is Nicolas";
        // forgefmt: disable-next-line
        uint256[512] memory expected_hash = [uint256(1470), 6782,10542,1136,4571,272,2988,5236,2678,1680,7633,9463,10293,217,6965,3448,1279,11288,3405,11815,9542,629,8010,2605,1520,1272,1585,2357,3050,866,3539,3791,930,3874,725,6757,2047,7817,10860,6903,11798,4458,1301,2832,6079,4452,6769,8438,1732,11471,346,9559,11110,9056,1726,2444,10148,2978,3341,6919,5955,8991,4831,1520,8921,5257,5804,3338,3187,7271,9559,10687,10567,5601,4339,3887,3013,6489,2959,9706,1259,6320,4894,6611,11806,836,10699,8121,8691,3898,12103,7095,4335,11326,888,4585,7752,11596,5973,4522,4495,1602,7978,6323,3282,4701,4347,7943,8143,7640,1307,8539,3020,12008,1331,12188,5153,9621,5566,6153,2960,2243,4482,2157,8507,2138,685,10176,10034,2644,2970,7655,1118,5212,10544,347,539,7959,2253,9831,1834,4430,3369,5333,9843,173,7029,2676,3442,9681,11635,222,5599,4650,3000,7205,5421,2547,4258,7237,3828,7866,4204,4665,5195,9965,1644,8046,7868,2555,7283,3150,11744,4847,9099,11520,2333,1893,11575,2216,8479,12249,7855,7581,6756,5414,6882,3205,6869,10786,1755,2883,9917,2403,8941,1320,5126,2623,6139,5655,3112,5093,10397,3383,2050,10912,1044,2281,10603,7358,5198,5939,8282,1030,6505,6603,7068,8234,3923,6851,10294,9124,885,11320,340,836,523,2668,6697,6566,5145,2224,8035,7017,7527,3040,8185,5773,3028,11402,11775,4816,5225,3689,11844,1935,5998,5357,2035,37,8505,2701,1376,2737,11285,5956,1283,5094,1084,9263,5714,7489,2325,10793,303,2979,10607,7813,8625,7632,4124,5174,2663,4615,11977,10012,4508,150,5768,336,9999,5639,6062,10525,6397,5320,9466,1954,2607,8987,1618,11303,6721,8745,6967,9684,272,3889,2732,4657,12253,6825,4743,5901,1838,8405,3798,6862,10475,11583,5356,5618,10986,11593,5476,3192,2464,5834,1467,3467,7464,8118,1755,6604,10375,3627,7641,7904,5285,5697,11556,2329,11658,4417,10390,7502,11502,2716,2088,3272,7364,2077,8540,10573,2761,11858,12153,6053,950,11100,5378,9362,7595,1057,4290,11147,5045,3070,10682,12002,7048,6054,8140,1397,1119,9063,3659,9631,11086,7762,10116,561,278,7015,4180,9858,6456,4715,3315,12153,4025,8727,1953,8355,7362,5374,2029,2847,9530,5011,9971,6189,8939,5218,6803,11168,10165,450,5355,3266,10932,3914,9300,4520,12166,9207,1214,1194,7101,1349,4373,6724,7254,4050,3832,3788,7659,7344,5984,4044,2598,10363,3913,10688,3902,9119,7083,11935,10308,1517,4720,5018,2240,4662,5271,2182,2967,3495,5449,7672,6231,9924,6486,1639,10525,2623,4736,5481,7955,8212,12082,5039,5507,6086,8517,7011,9299,9312,11284,4553,934,3318,9289,2729,7007,10957,10436,5847,7306,3877,11242,10147,6116,1270,5616,4462,996,6335,6704,6188,3363,763,11874,2071,4978,3636,1183,1888,11908,2800,6411,4687,1188,670,4493,8662,2442,10687,5557,8894,9126,8637,1088,3692,588,8116,10536,7838,8243,327,5382,5133];
        uint256 q = 12289;
        uint256 n = 512;
        uint256[] memory hash = hashToPointRIP(salt, message);
        for (uint256 i = 0; i < n; i++) {
            assertEq(hash[i], expected_hash[i]);
        }
    }

    function testVector3() public pure {
        bytes memory salt =
            "\x95\x52\x2a\x6b\xcd\x16\xcf\x86\xf3\xd1\x22\x10\x9e\x3b\x1f\xdd\x94\x3b\x6a\xec\x46\x8a\x2d\x62\x1a\x7c\x06\xc6\xa9\x57\xc6\x2b\x54\xda\xfc\x3b\xe8\x75\x67\xd6";
        bytes memory message = "We are ZKNox";
        // forgefmt: disable-next-line
        uint256[512] memory expected_hash = [uint256(711), 7375,6114,5621,5974,6851,10117,5175,5525,3064,5667,6017,247,7687,1073,6294,9984,11976,11212,793,11853,8706,11707,10672,7249,5146,568,4059,9495,11420,2886,6627,1184,8208,81,4971,8327,11136,676,11528,2983,9553,10214,8134,4897,8568,9167,4302,3708,4504,4028,6429,1482,9124,648,10241,10895,538,11764,11209,10408,7712,8215,9180,10038,9125,11263,11614,9404,7137,7627,719,1561,4120,5283,1997,8513,1391,10586,6308,8699,7630,10624,1675,2697,10324,182,976,5470,5569,11349,4344,10386,1272,8008,7526,9081,10754,6927,7505,9057,2651,8438,3414,5752,10173,2048,12124,6824,1997,4192,1109,5545,9291,9455,8658,7729,2789,7410,261,9395,87,5647,7880,11130,10180,9220,4929,11535,9653,3243,5271,3967,2836,6411,11605,8554,5300,4642,316,1100,6187,2139,2434,2522,1665,542,6829,981,315,2823,10134,10788,3943,2714,8173,4736,1558,2158,4013,6156,6740,4324,4034,9081,11481,3678,6062,10926,9646,2703,2612,9628,9106,1516,110,6995,4429,2143,4907,11803,2932,2357,6420,7591,634,6837,9908,2803,4644,9545,10721,12062,4370,2283,11366,11610,1599,8379,293,9057,102,7363,1380,5318,11790,1287,9944,11654,3538,8411,9047,5475,3257,7833,8526,5174,11704,197,7914,4962,5220,1617,10314,1240,5223,2291,2165,1973,12276,588,6858,7507,11065,1605,11921,3181,2724,6210,998,3091,2394,11910,11099,9478,5029,12053,3397,4081,9067,6798,9699,1381,8694,6450,788,7809,4846,463,6722,3999,2126,11513,8827,2517,4934,4659,10080,3210,12260,4331,8036,4923,7740,284,7455,349,10167,7826,9029,9666,2299,4241,6715,5326,10382,2280,1836,750,7793,12063,3297,2074,2202,244,7287,8317,2172,8985,4868,2220,2974,8974,6343,7717,3271,8091,1281,650,7577,7181,1137,176,6015,8882,7076,3789,10207,11517,7069,12064,9606,4917,856,6501,6832,10425,8177,8637,7115,10910,3954,4055,954,5926,808,3872,6705,691,1183,6640,3165,8685,2320,8800,3396,1645,2492,520,1098,3578,10818,2911,2009,890,9965,3705,1896,2057,6229,11003,6650,8233,7563,10830,9230,10107,9427,8665,240,2491,11845,4192,11470,12058,1879,11002,10427,3089,8218,450,12037,5648,5143,3565,8573,6133,10284,6696,4574,11998,3773,3704,12157,2995,3807,8410,3283,2146,7274,2773,4190,240,4777,7960,4582,7974,5113,6080,7087,9438,471,9276,11170,1682,9551,9841,8461,759,68,3848,6593,10752,9371,134,5953,1102,10201,11244,2245,10398,3864,7529,8911,7867,4046,2224,11004,667,2816,11906,1844,6285,11889,5642,2879,2747,8358,789,5944,7577,3819,7400,9565,10439,11943,8371,4779,6252,12068,6992,11109,9630,6593,11239,10990,2134,9221,1915,10188,11659,2443,3733,2732,11977,11229,10833,9558,3052,3425,7536,9889,2157,7166,3841,10575,9827,2740,5596,11943,5514,2557,5131,2416,6539,718,4991,9657,7791,2605,691,4475,11016,4190,11722,9198,7320,5448,12045,4309,3138,11319];
        uint256 q = 12289;
        uint256 n = 512;
        uint256[] memory hash = hashToPointRIP(salt, message);
        for (uint256 i = 0; i < n; i++) {
            assertEq(hash[i], expected_hash[i]);
        }
    }
}
