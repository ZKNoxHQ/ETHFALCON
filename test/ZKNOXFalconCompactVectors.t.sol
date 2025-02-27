// code generated using pythonref/generate_falcon_compact_test_vectors.py.
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_NTT.sol";
import "../src/ZKNOX_falcon_compact.sol";

contract ZKNOX_FalconTest is Test {
    ZKNOX_falcon_compact falcon;
    //exemple of stateless initialisation, no external contract provided
    ZKNOX_NTT ntt = new ZKNOX_NTT(address(0), address(0), 12289, 12265);
    // forgefmt: disable-next-line
        uint256[1024] psi_rev = [uint256(1), 1479, 4043, 7143, 5736, 4134, 1305, 722, 1646, 1212, 6429, 9094, 3504, 8747, 9744, 8668, 4591, 6561, 5023, 6461, 10938, 4978, 6512, 8961, 11340, 9664, 9650, 4821, 563, 9314, 2744, 3006, 1000, 4320, 12208, 3091, 9326, 4896, 2366, 9238, 11563, 7678, 1853, 140, 1635, 9521, 11112, 4255, 7203, 10963, 9088, 9275, 790, 955, 11119, 2319, 9542, 4846, 3135, 3712, 9995, 11227, 3553, 7484, 544, 5791, 11950, 2468, 11267, 9, 9447, 11809, 10616, 8011, 7300, 6958, 1381, 2525, 4177, 8705, 2837, 5374, 4354, 130, 2396, 4452, 3296, 8340, 12171, 9813, 2197, 5067, 11336, 3748, 5767, 827, 3284, 2881, 5092, 10200, 10276, 9000, 9048, 11560, 10593, 10861, 334, 2426, 4632, 5755, 11029, 4388, 10530, 3707, 3694, 7110, 11934, 3382, 2548, 8058, 4890, 6378, 9558, 3932, 5542, 12144, 3459, 3637, 1663, 1777, 1426, 7635, 2704, 5291, 7351, 8653, 9140, 160, 12286, 7852, 2166, 8374, 7370, 12176, 3364, 10600, 9018, 4057, 2174, 7917, 2847, 7875, 7094, 9509, 10805, 4895, 2305, 5042, 4053, 9644, 3985, 7384, 476, 3531, 420, 6730, 2178, 1544, 9273, 243, 9289, 11618, 3136, 5191, 8889, 9890, 9103, 6882, 10163, 1630, 11136, 2884, 8241, 10040, 3247, 9603, 2969, 3978, 6957, 3510, 9919, 9424, 7575, 8146, 1537, 12047, 8585, 2678, 5019, 545, 7404, 1017, 10657, 7205, 10849, 8526, 3066, 12262, 11244, 2859, 2481, 7277, 2912, 5698, 354, 7428, 390, 11516, 3778, 8456, 442, 2401, 5101, 11222, 4976, 10682, 875, 3780, 7278, 11287, 5088, 4284, 6022, 9302, 2437, 3646, 10102, 9723, 6039, 9867, 11854, 7952, 10911, 1912, 11796, 8193, 9908, 5444, 9041, 1207, 5277, 1168, 11885, 4645, 1065, 2143, 3957, 2839, 10162, 151, 11858, 1579, 2505, 5906, 52, 3174, 1323, 2766, 3336, 6055, 6415, 677, 3445, 7509, 4698, 5057, 12097, 10968, 10240, 4912, 5241, 9369, 3127, 4169, 3482, 787, 6821, 11279, 12231, 241, 11286, 3532, 11404, 6008, 10333, 7280, 2844, 3438, 8077, 975, 5681, 8812, 142, 1105, 4080, 421, 3602, 6221, 4624, 6212, 3263, 8689, 5886, 4782, 5594, 3029, 4213, 504, 605, 9987, 2033, 8291, 10367, 8410, 11316, 11035, 10930, 5435, 3710, 6196, 6950, 5446, 8301, 468, 11973, 11907, 6152, 4948, 11889, 10561, 6153, 6427, 3643, 5415, 56, 9090, 5206, 6760, 1702, 10302, 11635, 3565, 5315, 8214, 7373, 4324, 10120, 11767, 5079, 3262, 11011, 2344, 6715, 1973, 5925, 1018, 3514, 11248, 7500, 7822, 5537, 4749, 8500, 12142, 5456, 7840, 6844, 8429, 7753, 1050, 6118, 3818, 9606, 1190, 5876, 2281, 2031, 5333, 8298, 8320, 12133, 2767, 453, 6381, 418, 3772, 5429, 4774, 1293, 7552, 2361, 1843, 9259, 4115, 218, 2908, 8855, 8760, 2882, 10484, 1954, 2051, 2447, 6147, 576, 3963, 1858, 7535, 3315, 11863, 2925, 347, 3757, 1975, 10596, 3009, 174, 11566, 9551, 5868, 2655, 6554, 1512, 11939, 5383, 10474, 9087, 7796, 6920, 10232, 6374, 1483, 49, 11026, 1489, 2500, 10706, 5942, 1404, 11964, 11143, 948, 4049, 3728, 1159, 5990, 652, 5766, 6190, 11994, 4016, 4077, 2919, 3762, 6328, 7183, 10695, 1962, 7991, 8960, 12121, 9597, 7105, 1200, 6122, 9734, 3956, 1360, 6119, 5297, 3054, 6803, 9166, 1747, 5919, 4433, 3834, 5257, 683, 2459, 8633, 12225, 9786, 9341, 6507, 1566, 11454, 6224, 3570, 8049, 3150, 1319, 4046, 11580, 1958, 7967, 2078, 1112, 11231, 8210, 11367, 441, 1826, 9363, 9118, 4489, 3708, 3238, 11153, 3449, 7080, 1092, 3359, 3205, 8024, 8611, 10361, 11825, 2068, 10900, 4404, 346, 3163, 8257, 7449, 6127, 12164, 11749, 10763, 4222, 8051, 11677, 8921, 8062, 7228, 11071, 11851, 3515, 9011, 5993, 6877, 8080, 1536, 10568, 4103, 9860, 11572, 8700, 1373, 2982, 3448, 11946, 4538, 1908, 4727, 11081, 1866, 7078, 10179, 716, 10125, 6873, 1705, 2450, 11475, 416, 10224, 5826, 7725, 8794, 1756, 4145, 8755, 8328, 5063, 4176, 8524, 10771, 2461, 2275, 8022, 5653, 6693, 6302, 11710, 3889, 212, 6323, 9175, 2769, 5734, 1176, 5508, 11014, 4860, 11164, 11158, 10844, 11841, 1014, 7508, 7365, 10962, 3607, 5232, 8347, 12221, 10029, 7723, 5836, 3200, 1535, 9572, 60, 7784, 10032, 10872, 5676, 3087, 6454, 7406, 3975, 7326, 8545, 2528, 3056, 5845, 5588, 11877, 5102, 1255, 506, 10897, 5784, 9615, 2212, 3338, 9013, 1178, 9513, 6811, 8778, 10347, 3408, 1165, 2575, 10453, 425, 11897, 10104, 377, 4578, 375, 1620, 1038, 11366, 6085, 4167, 6092, 2231, 2800, 12096, 1522, 2151, 8946, 8170, 5002, 12269, 7681, 5163, 10545, 1314, 2894, 3654, 11951, 3947, 9834, 6599, 7350, 7174, 1248, 2442, 8330, 6492, 6330, 10141, 5724, 10964, 1945, 1029, 8945, 6691, 10397, 3624, 6825, 4906, 4670, 512, 7735, 11295, 9389, 12050, 1804, 1403, 6195, 7100, 406, 10602, 7021, 12143, 8914, 9998, 7954, 3393, 8464, 8054, 7376, 8761, 11667, 1737, 4499, 5672, 8307, 9342, 11653, 5609, 4605, 2689, 180, 8151, 5219, 1409, 204, 6780, 9806, 2054, 1344, 9247, 463, 8882, 3981, 1468, 4475, 7043, 3017, 1236, 9168, 4705, 2600, 11232, 4739, 4251, 1226, 6771, 11925, 2360, 3028, 5216, 11839, 10345, 11711, 5368, 11779, 7628, 2622, 6903, 8929, 7605, 7154, 12226, 8481, 8619, 2373, 7302, 10891, 9199, 826, 5043, 5789, 8787, 6671, 10631, 9224, 1506, 7806, 5703, 4719, 11538, 6389, 11379, 4693, 9951, 11872, 9996, 6138, 8820, 4443, 8871, 7186, 10398, 1802, 10734, 1590, 4411, 1223, 2334, 2946, 6828, 2637, 4510, 881, 365, 10362, 1015, 7250, 6742, 2485, 904, 24, 10918, 11009, 11675, 980, 11607, 5082, 7699, 5207, 8239, 844, 7087, 3221, 8016, 8452, 2595, 5289, 6627, 567, 2941, 1406, 2633, 6940, 2945, 3232, 11996, 3769, 7434, 3944, 8190, 6759, 5604, 11024, 9282, 10118, 8809, 9169, 6184, 6643, 6086, 8753, 5370, 8348, 8536, 1282, 3572, 9457, 2021, 4730, 3229, 1706, 3929, 5054, 3154, 9004, 7929, 12282, 1936, 8566, 11444, 11520, 5526, 50, 216, 767, 3805, 4153, 10076, 1279, 11424, 9617, 5170, 12100, 3116, 10080, 1763, 3815, 1734, 1350, 5832, 8420, 4423, 1530, 1694, 10036, 10421, 9559, 5411, 4820, 1160, 9195, 7771, 2840, 9811, 4194, 9270, 7315, 4565, 7211, 10506, 944, 7519, 7002, 8620, 7624, 6883, 3020, 5673, 5410, 1251, 10499, 7014, 2035, 11249, 6164, 10407, 8176, 12217, 10447, 3840, 2712, 4834, 2828, 4352, 1241, 4378, 3451, 4094, 3045, 5781, 9646, 11194, 7592, 8711, 8823, 10588, 7785, 11511, 2626, 530, 10808, 9332, 9349, 2046, 8972, 9757, 8957, 12150, 3268, 3795, 1849, 6513, 4523, 4301, 457, 8, 8835, 3758, 8071, 4390, 10013, 982, 2593, 879, 9687, 10388, 11787, 7171, 6063, 8496, 8443, 1573, 5969, 4649, 9360, 6026, 1030, 11823, 10608, 8468, 11415, 9988, 5650, 12119, 648, 12139, 2307, 8000, 11498, 9855, 9416, 2827, 9754, 11169, 21, 6481];
    // forgefmt: disable-next-line
        uint256[1024] psi_inv_rev = [uint256(1), 10810, 5146, 8246, 11567, 10984, 8155, 6553, 3621, 2545, 3542, 8785, 3195, 5860, 11077, 10643, 9283, 9545, 2975, 11726, 7468, 2639, 2625, 949, 3328, 5777, 7311, 1351, 5828, 7266, 5728, 7698, 4805, 8736, 1062, 2294, 8577, 9154, 7443, 2747, 9970, 1170, 11334, 11499, 3014, 3201, 1326, 5086, 8034, 1177, 2768, 10654, 12149, 10436, 4611, 726, 3051, 9923, 7393, 2963, 9198, 81, 7969, 11289, 8652, 8830, 145, 6747, 8357, 2731, 5911, 7399, 4231, 9741, 8907, 355, 5179, 8595, 8582, 1759, 7901, 1260, 6534, 7657, 9863, 11955, 1428, 1696, 729, 3241, 3289, 2013, 2089, 7197, 9408, 9005, 11462, 6522, 8541, 953, 7222, 10092, 2476, 118, 3949, 8993, 7837, 9893, 12159, 7935, 6915, 9452, 3584, 8112, 9764, 10908, 5331, 4989, 4278, 1673, 480, 2842, 12280, 1022, 9821, 339, 6498, 11745, 10146, 11224, 7644, 404, 11121, 7012, 11082, 3248, 6845, 2381, 4096, 493, 10377, 1378, 4337, 435, 2422, 6250, 2566, 2187, 8643, 9852, 2987, 6267, 8005, 7201, 1002, 5011, 8509, 11414, 1607, 7313, 1067, 7188, 9888, 11847, 3833, 8511, 773, 11899, 4861, 11935, 6591, 9377, 5012, 9808, 9430, 1045, 27, 9223, 3763, 1440, 5084, 1632, 11272, 4885, 11744, 7270, 9611, 3704, 242, 10752, 4143, 4714, 2865, 2370, 8779, 5332, 8311, 9320, 2686, 9042, 2249, 4048, 9405, 1153, 10659, 2126, 5407, 3186, 2399, 3400, 7098, 9153, 671, 3000, 12046, 3016, 10745, 10111, 5559, 11869, 8758, 11813, 4905, 8304, 2645, 8236, 7247, 9984, 7394, 1484, 2780, 5195, 4414, 9442, 4372, 10115, 8232, 3271, 1689, 8925, 113, 4919, 3915, 10123, 4437, 3, 12129, 3149, 3636, 4938, 6998, 9585, 4654, 10863, 10512, 10626, 11848, 922, 4079, 1058, 11177, 10211, 4322, 10331, 709, 8243, 10970, 9139, 4240, 8719, 6065, 835, 10723, 5782, 2948, 2503, 64, 3656, 9830, 11606, 7032, 8455, 7856, 6370, 10542, 3123, 5486, 9235, 6992, 6170, 10929, 8333, 2555, 6167, 11089, 5184, 2692, 168, 3329, 4298, 10327, 1594, 5106, 5961, 8527, 9370, 8212, 8273, 295, 6099, 6523, 11637, 6299, 11130, 8561, 8240, 11341, 1146, 325, 10885, 6347, 1583, 9789, 10800, 1263, 12240, 10806, 5915, 2057, 5369, 4493, 3202, 1815, 6906, 350, 10777, 5735, 9634, 6421, 2738, 723, 12115, 9280, 1693, 10314, 8532, 11942, 9364, 426, 8974, 4754, 10431, 8326, 11713, 6142, 9842, 10238, 10335, 1805, 9407, 3529, 3434, 9381, 12071, 8174, 3030, 10446, 9928, 4737, 10996, 7515, 6860, 8517, 11871, 5908, 11836, 9522, 156, 3969, 3991, 6956, 10258, 10008, 6413, 11099, 2683, 8471, 6171, 11239, 4536, 3860, 5445, 4449, 6833, 147, 3789, 7540, 6752, 4467, 4789, 1041, 8775, 11271, 6364, 10316, 5574, 9945, 1278, 9027, 7210, 522, 2169, 7965, 4916, 4075, 6974, 8724, 654, 1987, 10587, 5529, 7083, 3199, 12233, 6874, 8646, 5862, 6136, 1728, 400, 7341, 6137, 382, 316, 11821, 3988, 6843, 5339, 6093, 8579, 6854, 1359, 1254, 973, 3879, 1922, 3998, 10256, 2302, 11684, 11785, 8076, 9260, 6695, 7507, 6403, 3600, 9026, 6077, 7665, 6068, 8687, 11868, 8209, 11184, 12147, 3477, 6608, 11314, 4212, 8851, 9445, 5009, 1956, 6281, 885, 8757, 1003, 12048, 58, 1010, 5468, 11502, 8807, 8120, 9162, 2920, 7048, 7377, 2049, 1321, 192, 7232, 7591, 4780, 8844, 11612, 5874, 6234, 8953, 9523, 10966, 9115, 12237, 6383, 9784, 10710, 431, 12138, 2127, 9450, 8332, 5808, 12268, 1120, 2535, 9462, 2873, 2434, 791, 4289, 9982, 150, 11641, 170, 6639, 2301, 874, 3821, 1681, 466, 11259, 6263, 2929, 7640, 6320, 10716, 3846, 3793, 6226, 5118, 502, 1901, 2602, 11410, 9696, 11307, 2276, 7899, 4218, 8531, 3454, 12281, 11832, 7988, 7766, 5776, 10440, 8494, 9021, 139, 3332, 2532, 3317, 10243, 2940, 2957, 1481, 11759, 9663, 778, 4504, 1701, 3466, 3578, 4697, 1095, 2643, 6508, 9244, 8195, 8838, 7911, 11048, 7937, 9461, 7455, 9577, 8449, 1842, 72, 4113, 1882, 6125, 1040, 10254, 5275, 1790, 11038, 6879, 6616, 9269, 5406, 4665, 3669, 5287, 4770, 11345, 1783, 5078, 7724, 4974, 3019, 8095, 2478, 9449, 4518, 3094, 11129, 7469, 6878, 2730, 1868, 2253, 10595, 10759, 7866, 3869, 6457, 10939, 10555, 8474, 10526, 2209, 9173, 189, 7119, 2672, 865, 11010, 2213, 8136, 8484, 11522, 12073, 12239, 6763, 769, 845, 3723, 10353, 7, 4360, 3285, 9135, 7235, 8360, 10583, 9060, 7559, 10268, 2832, 8717, 11007, 3753, 3941, 6919, 3536, 6203, 5646, 6105, 3120, 3480, 2171, 3007, 1265, 6685, 5530, 4099, 8345, 4855, 8520, 293, 9057, 9344, 5349, 9656, 10883, 9348, 11722, 5662, 7000, 9694, 3837, 4273, 9068, 5202, 11445, 4050, 7082, 4590, 7207, 682, 11309, 614, 1280, 1371, 12265, 11385, 9804, 5547, 5039, 11274, 1927, 11924, 11408, 7779, 9652, 5461, 9343, 9955, 11066, 7878, 10699, 1555, 10487, 1891, 5103, 3418, 7846, 3469, 6151, 2293, 417, 2338, 7596, 910, 5900, 751, 7570, 6586, 4483, 10783, 3065, 1658, 5618, 3502, 6500, 7246, 11463, 3090, 1398, 4987, 9916, 3670, 3808, 63, 5135, 4684, 3360, 5386, 9667, 4661, 510, 6921, 578, 1944, 450, 7073, 9261, 9929, 364, 5518, 11063, 8038, 7550, 1057, 9689, 7584, 3121, 11053, 9272, 5246, 7814, 10821, 8308, 3407, 11826, 3042, 10945, 10235, 2483, 5509, 12085, 10880, 7070, 4138, 12109, 9600, 7684, 6680, 636, 2947, 3982, 6617, 7790, 10552, 622, 3528, 4913, 4235, 3825, 8896, 4335, 2291, 3375, 146, 5268, 1687, 11883, 5189, 6094, 10886, 10485, 239, 2900, 994, 4554, 11777, 7619, 7383, 5464, 8665, 1892, 5598, 3344, 11260, 10344, 1325, 6565, 2148, 5959, 5797, 3959, 9847, 11041, 5115, 4939, 5690, 2455, 8342, 338, 8635, 9395, 10975, 1744, 7126, 4608, 20, 7287, 4119, 3343, 10138, 10767, 193, 9489, 10058, 6197, 8122, 6204, 923, 11251, 10669, 11914, 7711, 11912, 2185, 392, 11864, 1836, 9714, 11124, 8881, 1942, 3511, 5478, 2776, 11111, 3276, 8951, 10077, 2674, 6505, 1392, 11783, 11034, 7187, 412, 6701, 6444, 9233, 9761, 3744, 4963, 8314, 4883, 5835, 9202, 6613, 1417, 2257, 4505, 12229, 2717, 10754, 9089, 6453, 4566, 2260, 68, 3942, 7057, 8682, 1327, 4924, 4781, 11275, 448, 1445, 1131, 1125, 7429, 1275, 6781, 11113, 6555, 9520, 3114, 5966, 12077, 8400, 579, 5987, 5596, 6636, 4267, 10014, 9828, 1518, 3765, 8113, 7226, 3961, 3534, 8144, 10533, 3495, 4564, 6463, 2065, 11873, 814, 9839, 10584, 5416, 2164, 11573, 2110, 5211, 10423, 1208, 7562, 10381, 7751, 343, 8841, 9307, 10916, 3589, 717, 2429, 8186, 1721, 10753, 4209, 5412, 6296, 3278, 8774, 438, 1218, 5061, 4227, 3368, 612, 4238, 8067, 1526, 540, 125, 6162, 4840, 4032, 9126, 11943, 7885, 1389, 10221, 464, 1928, 3678, 4265, 9084, 8930, 11197, 5209, 8840, 1136, 9051, 8581, 7800, 3171, 2926, 10463];

    //stateful initialisation
    function setUp() public {
        bytes memory bytecode_psirev = abi.encodePacked(psi_rev);

        address a_psirev; //address of the precomputations bytecode contract
        a_psirev = address(uint160(0xcaca)); //here it is etched, use create in the future
        vm.etch(a_psirev, bytecode_psirev); //pushing psirev bytecode into contract todo : replace with create

        bytes memory bytecode_psiInvrev = abi.encodePacked(psi_inv_rev);

        address a_psiInvrev; //address of the precomputations bytecode contract
        a_psiInvrev = address(uint160(0xa5a5)); //here it is etched, use create in the future
        vm.etch(a_psiInvrev, bytecode_psiInvrev); //pushing psirev bytecode into contract todo : replace with create

        ntt.update(a_psirev, a_psiInvrev, 12289, 12265); //update ntt with outer contract

        falcon = new ZKNOX_falcon_compact(ntt);
    }

    function testVector0() public view {
        // public key
        // forgefmt: disable-next-line
        uint[32] memory tmp_pk = [uint(12419220082088592572435430479873639106245158704968706145829826897511072342318), 12406893752074795063981555124397144870995208831511296034148492772359662405936,11382304137089395723527484149210690251172702713008627762303512269727654152850,9023316618435350563025944668543094212033316048304069234612565141806408804289,18652907308120603214945044123794163967418878278474148660994602989081969099227,9445648688722365978222149185598344920813640168827781042306522083884472405736,6102747242978755406754164506517317623200513039216143239507493576861653606784,7062161186165216359471872158335623039567543164009364925185641223931602801907,116897092268967509459127668134995557061134651438562301347069829349287075530,252678572002527805905326072628251628208434456557734355541022494991334835167,21182824875375670545923673700425681088980811646368472014910404891119742943940,10081941116816495048898841878267493849055354352889654295709652150660095086891,5281364050079205227022061384041075885830252771036534974931199492272439037666,10207241705976198578651432504627028988000723056522003809590615893267562694012,11035982243994909377173625227360546057761681426632194497931157060309559029516,4134662940811675723890906031297969520861942693535464126143398200857869027431,3790170119073194564564025684642472948655183817292957561008508868980666674046,2003792460338429988087814626923365814548102349288907437283508374149359283354,49673433593111962105143551227906790949025282006124931474583823101616200644,3012774799969893700979690157572038921869925338381850722130415309601247269021,6099203359253881377247209951241483453979252198249148499736400839825519810866,18783580226085337219283424685063887850994680925451233610184486259025386282635,5457834963850462323766830105843519703756281691807058541562744670223999175418,409998569559228517967697619007743899962889872767220000583111902927028690670,6818293424474131060875329861731389804952013645206281647903100967191790890374,11834605578470703398416360107323650067684494025975913751061251108948323142079,1903075515454714970362845626297083817046465398216037386876703300216368142241,14537874312671405978059240364788550077303984452594189950379847573231252676200,16027370708344224513479260184091696463554430788661445955029738323181863445924,17640337352197077800465068638991935390393709437834044530010934176302742504644,12172115155274833865458398115434116447966128197097634526763252201857418533557,4410184670441942184395353849559338537083851660850871884432724316572555356379];
        uint256[] memory pk = new uint256[](512);
        for (uint256 i = 0; i < 32; i++) {
            pk[i] = tmp_pk[i];
        }
        // signature s2
        // forgefmt: disable-next-line
        uint[32] memory tmp_s2 = [uint(290093910866615732134712510711399460403569264381710451764998993912354516987), 23294688046888675336023881946381614331974127665022126442842278268369174637,496494728367860443245592910655546047867510078319673337469421111009636331468,7072920055862368565764904239260101619356553840776713116679213883866677270,21311709569988779015338503734400165559023680970741621653822586471153146527781,111312017109004435681040112255897123533766851930477384238258251916279164794,88670245098220810789487412484937713587720655688123478245382055077886504791,328964465442753307343779126311922999067172552121460590416686819674805645249,21502851192377344974677720091383491628103172940769909797141445589994887512387,5627920847635758858566843431442002562936947058222695711463693100139360100,21431857623681315288933966461423443819183840149553936598510141094328955830308,21513136250262619711231506136167889442562961681116045540186300404247453171889,157577033078164060199277775900361469822654466566183776269147086776893124336,83372211205253838500310696903816367141996568234385993087675719716688429116,353376988712210556848922668941644663928849762090033949381995016709698879621,21652712774031731141746166176420263113821164592915536277161025084583464415076,81598592217034589324780593611216049017701949159390610426608392358235275307,21509921039010805139733327459402746597020615583989782593635151589721612157114,21508158882908122413491952720591596305028555087993752742022272852636340584526,21407126423925543640874097367958078745413976612003616673797639326268766564228,150512804043819351386699326517228907284518001449880737190198073478267273438,21660100068921325183492252640798391213972113268072175023036821225677818310528,21486628669456466626254611453903485281968215437503649424454353073937687511334,21697210629161992372357118858950275018825639475949200247798747451646852595748,21644207805428569922450455380964932987166486980464183825652009273644620394411,404934435846955401297075594203959382460453070954769358588172502690697314471,74537571517205863809813961046887152101860084589476447069528187823956099261,38873439298323676235007618460019194991697800041752436004358538962083262383,173152958467187375232602546034444540495117769175691458023294445285913854076,21674237217903413808515430117098667542398170123325112962470901175538033307547,21679216639181971368260143510423269239492700569406357749179392013661296209879,70674880166754793750003755396911748946971220421867085467822785712871452594];
        ZKNOX_falcon_compact.CompactSignature memory sig;
        for (uint256 i = 0; i < 32; i++) {
            sig.s2[i] = tmp_s2[i];
        }
        // message
        bytes memory message = "My name is Renaud";
        sig.salt =
            "\x35\x00\x31\x8f\x75\xad\x20\xf0\xaa\x20\x62\xba\x1c\x34\x8a\xfe\xaa\x49\x23\x87\xa4\x63\xeb\x8c\x28\xaf\x77\x9d\x6a\x3e\xa6\x96\xeb\xb9\x66\x0c\xcf\xf5\x06\x2d";
        bool result = falcon.verify(message, sig, pk);
        assertEq(true, result);
    }

    function testVector1() public view {
        // public key
        // forgefmt: disable-next-line
        uint[32] memory tmp_pk = [uint(12419220082088592572435430479873639106245158704968706145829826897511072342318), 12406893752074795063981555124397144870995208831511296034148492772359662405936,11382304137089395723527484149210690251172702713008627762303512269727654152850,9023316618435350563025944668543094212033316048304069234612565141806408804289,18652907308120603214945044123794163967418878278474148660994602989081969099227,9445648688722365978222149185598344920813640168827781042306522083884472405736,6102747242978755406754164506517317623200513039216143239507493576861653606784,7062161186165216359471872158335623039567543164009364925185641223931602801907,116897092268967509459127668134995557061134651438562301347069829349287075530,252678572002527805905326072628251628208434456557734355541022494991334835167,21182824875375670545923673700425681088980811646368472014910404891119742943940,10081941116816495048898841878267493849055354352889654295709652150660095086891,5281364050079205227022061384041075885830252771036534974931199492272439037666,10207241705976198578651432504627028988000723056522003809590615893267562694012,11035982243994909377173625227360546057761681426632194497931157060309559029516,4134662940811675723890906031297969520861942693535464126143398200857869027431,3790170119073194564564025684642472948655183817292957561008508868980666674046,2003792460338429988087814626923365814548102349288907437283508374149359283354,49673433593111962105143551227906790949025282006124931474583823101616200644,3012774799969893700979690157572038921869925338381850722130415309601247269021,6099203359253881377247209951241483453979252198249148499736400839825519810866,18783580226085337219283424685063887850994680925451233610184486259025386282635,5457834963850462323766830105843519703756281691807058541562744670223999175418,409998569559228517967697619007743899962889872767220000583111902927028690670,6818293424474131060875329861731389804952013645206281647903100967191790890374,11834605578470703398416360107323650067684494025975913751061251108948323142079,1903075515454714970362845626297083817046465398216037386876703300216368142241,14537874312671405978059240364788550077303984452594189950379847573231252676200,16027370708344224513479260184091696463554430788661445955029738323181863445924,17640337352197077800465068638991935390393709437834044530010934176302742504644,12172115155274833865458398115434116447966128197097634526763252201857418533557,4410184670441942184395353849559338537083851660850871884432724316572555356379];
        uint256[] memory pk = new uint256[](512);
        for (uint256 i = 0; i < 32; i++) {
            pk[i] = tmp_pk[i];
        }
        // signature s2
        // forgefmt: disable-next-line
        uint[32] memory tmp_s2 = [uint(21691584029425866367845503320412104453336730405297410283942887733321738027101), 159020850982932915177881936647104422414117768244460326451400317306701283552,21605335574348626171155479802742464841549200200065973423231779255048248688692,145207437028080073146240106357456734211537039280218646161779473859974332567,256196334229815974522673914049370188682867305832789516895493877536817676519,21508156483513520420412835507354878025975181363454609267913288807832944640125,21380617171667359072658557895174515114496911374896747969939434823379138064167,86903716582555936866547617835885248637877741876978287911715824738245542105,227925756716622983676931527401697513806371661490224823051634895568047636759,21554086602972189431963367359575153984343791939480203158665077175835094220976,21454827601144588400862184056685168369387093600290689505833160531748025597961,35337076129110515464221085213828154375305664049168561191475939405783379806,217652695993703727261178652773840714274244224607389474524084196668113825625,21557305706472433569728650297127247296867001757575661745208714589852288692036,535360731661455188996790331884867137080178164155401331200064614470352765094,21596501343953096107958456454950042009424278008048479778718540778071194742517,21432181731261891712573548773817579749833925048313590956576293178047399788891,21409216385921584346131743805068791565597933396087152666555500491403748638868,325430474763168138778568217466591058943719902571102675102557438574898118834,512386188016341095164499805722875564925727735315604074589519786118900428748,104246780688953575603745337257811025417080608559655436499033999506730844228,21382708940009781433057920257046271596408171938791881255428330906768839344265,21479885388830661861255050749787681428220933467939109835944346929974834757782,21580595326003685282329050730956264189246389821398325153274226186866167984032,373130299049190561183721992442010693464807280738133912953736289093211664377,392570824948713163321894454031179134253705796042335089221937003798608806128,279162083917976485368124796215187607396683933160171010026529053158890483450,21407446627182901356699455054209449309019024421096951402222309899581786095725,21578832603809099239098822324434704912415904552730537853395572230230250160284,286554393439588345224410166717898786053343413016059220209325677651281915785,111639391718270973252144418320413562274190687739253046474318003310560095988,21357973404506646548232006546299755360606743981553004164632645428964399001580];
        ZKNOX_falcon_compact.CompactSignature memory sig;
        for (uint256 i = 0; i < 32; i++) {
            sig.s2[i] = tmp_s2[i];
        }
        // message
        bytes memory message = "My name is Simon";
        sig.salt =
            "\xdb\xae\x77\x2d\xb2\x90\x58\xa8\x8f\x9b\xd8\x30\xe9\x57\xc6\x95\x34\x7c\x41\xb6\x16\x2a\x7e\xb9\xa9\xea\x13\xde\xf3\x4b\xe5\x6b\x8b\xbb\xb9\x64\xb3\x23\xd7\x67";
        bool result = falcon.verify(message, sig, pk);
        assertEq(true, result);
    }

    function testVector2() public view {
        // public key
        // forgefmt: disable-next-line
        uint[32] memory tmp_pk = [uint(12419220082088592572435430479873639106245158704968706145829826897511072342318), 12406893752074795063981555124397144870995208831511296034148492772359662405936,11382304137089395723527484149210690251172702713008627762303512269727654152850,9023316618435350563025944668543094212033316048304069234612565141806408804289,18652907308120603214945044123794163967418878278474148660994602989081969099227,9445648688722365978222149185598344920813640168827781042306522083884472405736,6102747242978755406754164506517317623200513039216143239507493576861653606784,7062161186165216359471872158335623039567543164009364925185641223931602801907,116897092268967509459127668134995557061134651438562301347069829349287075530,252678572002527805905326072628251628208434456557734355541022494991334835167,21182824875375670545923673700425681088980811646368472014910404891119742943940,10081941116816495048898841878267493849055354352889654295709652150660095086891,5281364050079205227022061384041075885830252771036534974931199492272439037666,10207241705976198578651432504627028988000723056522003809590615893267562694012,11035982243994909377173625227360546057761681426632194497931157060309559029516,4134662940811675723890906031297969520861942693535464126143398200857869027431,3790170119073194564564025684642472948655183817292957561008508868980666674046,2003792460338429988087814626923365814548102349288907437283508374149359283354,49673433593111962105143551227906790949025282006124931474583823101616200644,3012774799969893700979690157572038921869925338381850722130415309601247269021,6099203359253881377247209951241483453979252198249148499736400839825519810866,18783580226085337219283424685063887850994680925451233610184486259025386282635,5457834963850462323766830105843519703756281691807058541562744670223999175418,409998569559228517967697619007743899962889872767220000583111902927028690670,6818293424474131060875329861731389804952013645206281647903100967191790890374,11834605578470703398416360107323650067684494025975913751061251108948323142079,1903075515454714970362845626297083817046465398216037386876703300216368142241,14537874312671405978059240364788550077303984452594189950379847573231252676200,16027370708344224513479260184091696463554430788661445955029738323181863445924,17640337352197077800465068638991935390393709437834044530010934176302742504644,12172115155274833865458398115434116447966128197097634526763252201857418533557,4410184670441942184395353849559338537083851660850871884432724316572555356379];
        uint256[] memory pk = new uint256[](512);
        for (uint256 i = 0; i < 32; i++) {
            pk[i] = tmp_pk[i];
        }
        // signature s2
        // forgefmt: disable-next-line
        uint[32] memory tmp_s2 = [uint(104566126262026868288967838939735908658431033870107200681468850561422983336), 21407447328145293613177435074895859486284778762640944851111586008057356157267,21486627990557151756838381940674648228455857048920328732447648622791878979457,426138816371540055776233723368633648267082947859032698545292861224077045390,100711846578666217718195056092779100828748233800206572136902439191614455917,507415555706725332878728163192439012115776498311058539989938716155845804136,21283439958054369327961685498292057251900986034386576568006569248191183073200,175240543021377183460395961088593743266702652284082404978405556910130343904,215560604077694936599490316718257769599030586525189269365691831908038619094,157250790690395914360948188722391040681475735246890145022637612373355593806,21126190736047740979293605911551574357407039536568164576373159054215243104381,32133425649375621371023849412383448551802636924075567976582438686224089166,21419814372818271063732596867364798895932271674405241232655091700832542064741,21623001537713628991078239341657540969150359552804008264781076959865814855534,21481651108479637535706530735736429335172038665892391954130556287294559104933,111640335338283236951112509288689127066175240930433617627785475337998172160,23299459924126804077356352386149154631025292950794067360117371234415161336,21601801421907380693333255591054998621470217978464899596687415657160815292354,21553769742752407126524907203254551682289783635656232528442471449114832416390,599289666855987344783540427793276972089584765490402046015660112765428248438,12370010404997822984621643852516688432872277316748758032257291681684979856,21577066969895436434806719280943406038151441912739454286116579167034312949949,107784168325855245228504446827010228085378722016916141587580129112509722623,70675774806267792777203176073955647206111138972788322523564066692395499543,203516539489534105597485452068823111981498902721520224779643075184337170401,21455153390164737939892743223646615560854542851728729117024902762993194959232,572787095747808625199363430608165861007330672408627043757932622520525008847,21301111048583108547578445132839173740729510833480038172109645931186913607796,21182732834614667874216992069077410948167492087316897379939377246783246905305,115174002566644752077616324318117447582618846164570928010889146187032494335,167851824123660303830417958574223025084275311409547051696140531472258903606,21560836030607085585127943599167188792800439182963846519618473290150955909152];
        ZKNOX_falcon_compact.CompactSignature memory sig;
        for (uint256 i = 0; i < 32; i++) {
            sig.s2[i] = tmp_s2[i];
        }
        // message
        bytes memory message = "My name is Nicolas";
        sig.salt =
            "\x6a\xf1\xf6\x92\xe9\x49\x6c\x6d\x0b\x66\x83\x16\xec\xcb\x93\x27\x6a\xe6\xb6\x77\x4f\xa7\x28\xaa\xc3\x1f\xf4\x0a\x38\x31\x87\x60\xba\x53\x0a\xf5\xf0\x89\x98\x14";
        bool result = falcon.verify(message, sig, pk);
        assertEq(true, result);
    }

    function testVector3() public view {
        // public key
        // forgefmt: disable-next-line
        uint[32] memory tmp_pk = [uint(12419220082088592572435430479873639106245158704968706145829826897511072342318), 12406893752074795063981555124397144870995208831511296034148492772359662405936,11382304137089395723527484149210690251172702713008627762303512269727654152850,9023316618435350563025944668543094212033316048304069234612565141806408804289,18652907308120603214945044123794163967418878278474148660994602989081969099227,9445648688722365978222149185598344920813640168827781042306522083884472405736,6102747242978755406754164506517317623200513039216143239507493576861653606784,7062161186165216359471872158335623039567543164009364925185641223931602801907,116897092268967509459127668134995557061134651438562301347069829349287075530,252678572002527805905326072628251628208434456557734355541022494991334835167,21182824875375670545923673700425681088980811646368472014910404891119742943940,10081941116816495048898841878267493849055354352889654295709652150660095086891,5281364050079205227022061384041075885830252771036534974931199492272439037666,10207241705976198578651432504627028988000723056522003809590615893267562694012,11035982243994909377173625227360546057761681426632194497931157060309559029516,4134662940811675723890906031297969520861942693535464126143398200857869027431,3790170119073194564564025684642472948655183817292957561008508868980666674046,2003792460338429988087814626923365814548102349288907437283508374149359283354,49673433593111962105143551227906790949025282006124931474583823101616200644,3012774799969893700979690157572038921869925338381850722130415309601247269021,6099203359253881377247209951241483453979252198249148499736400839825519810866,18783580226085337219283424685063887850994680925451233610184486259025386282635,5457834963850462323766830105843519703756281691807058541562744670223999175418,409998569559228517967697619007743899962889872767220000583111902927028690670,6818293424474131060875329861731389804952013645206281647903100967191790890374,11834605578470703398416360107323650067684494025975913751061251108948323142079,1903075515454714970362845626297083817046465398216037386876703300216368142241,14537874312671405978059240364788550077303984452594189950379847573231252676200,16027370708344224513479260184091696463554430788661445955029738323181863445924,17640337352197077800465068638991935390393709437834044530010934176302742504644,12172115155274833865458398115434116447966128197097634526763252201857418533557,4410184670441942184395353849559338537083851660850871884432724316572555356379];
        uint256[] memory pk = new uint256[](512);
        for (uint256 i = 0; i < 32; i++) {
            pk[i] = tmp_pk[i];
        }
        // signature s2
        // forgefmt: disable-next-line
        uint[32] memory tmp_s2 = [uint(21672148474060821308360845546934434286441572504375869147931997424168877817907), 21633601299129011902706687159628945506745825953783714190220594238739589246863,222627556060072610040243117217382054474619768606458892967287638734844800951,21384479340805006716457632884459803765843524120923615320253211825176683937936,21439253190494831014895419990317903584161386138275599520794325910293350318252,341327002868945451119125495513923018411858066867205534798526362032716447839,21656571636948397294356628654055960273299715236914218921257421383355128360893,21465428171283652642511275008830184259061660973683919991927459908146970177251,114851318905749105456754362067958046373227366248914278563041805145970377004,21679215668706989745254855794748559569095961782450694513217768700835123822628,21591199962211919781209404176920076737917933641409299825038444684158133928145,21400382905504096886179835292276931148731930562168152407045132029414156665137,21320874140533559286713583335191522456509396330159451889716741948485782155193,886961491182036960864839542154109997931037096895728408595034749297856950049,21362951068493781165642744432501892671767570635539671655644510297800186658878,268886461939316184183825946642236506779415884713540691331845473352662855484,21711346128655608452066526280223062847012838338938858667405702877548296220587,166414665289105859068823875688810550906940032132742369771481650460358934663,88673205757562191180384557491676686285188257705660136120648019675809644563,21144182100986839079398865715130311926079310911793769038512781395138899542424,207048723871127713564813812771539424540772557873100666186221215112785964921,21385922992083366133672322583123223692767109608257182706548650417277469982836,349839713871354584596218309749835084790979730859434527872827144910056128596,81603746535859648826212297927314311295903995471440128687705493111969689528,40643386795637418114858652454649695007587882402979552018892891363462021294,268890640773345727171983590891204359459891811060709863327986735474644037528,199983249750949978334159986703076948545438709824857433969350448294084476975,793636238849465362010030652709329555794272111927560114884377791267579703250,224714395697976020055694155559710212564245489695983762952608861446796816265,21674238894336800130451809559209615032525084063649425902157458731935237680839,273862319590279455036398196383030172394806451618855097302480431257144864603,662575742330885468959310999107620036288627538992284898813964896145232506860];
        ZKNOX_falcon_compact.CompactSignature memory sig;
        for (uint256 i = 0; i < 32; i++) {
            sig.s2[i] = tmp_s2[i];
        }
        // message
        bytes memory message = "We are ZKNox";
        sig.salt =
            "\x96\x44\x29\x4a\xc4\xff\xb3\x09\x1e\xef\x01\x21\x9b\x3f\xe4\xfe\x46\x7f\x05\x89\x0c\xc5\x6a\xf9\x61\xdc\xe6\x8f\xdd\xbb\x77\x04\x71\x91\x37\x3e\xdc\x7d\xa9\x43";
        bool result = falcon.verify(message, sig, pk);
        assertEq(true, result);
    }
}
