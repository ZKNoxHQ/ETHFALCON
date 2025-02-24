// code generated using pythonref/generate_falcon_zknox_test_vectors.py.
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_NTT.sol";
import "../src/ZKNOX_falcon.sol";

contract ZKNOX_FalconTest is Test {
    ZKNOX_falcon falcon;
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

        falcon = new ZKNOX_falcon(ntt);
    }

    function testVector0() public view {
        // public key
        // forgefmt: disable-next-line
        uint[512] memory tmp_pk = [uint(8494), 9875,5391,1879,708,7214,6161,7426,130,4397,5498,8631,2407,9977,1931,7029,2352,991,9225,9158,8285,955,12093,4942,2664,778,3383,11334,11105,10565,3474,7022,2706,1183,6455,1113,1385,4181,5984,1364,6193,7574,2703,11943,2783,9363,10213,6442,10177,6408,8584,2766,1171,7190,253,3679,2625,7796,8043,5703,2065,459,1063,5107,475,7421,2950,1363,9991,2222,1222,2148,12181,10486,7239,2220,8612,10147,11233,10557,3816,7607,2043,9737,1487,6402,7156,4425,11155,8706,2669,9984,4688,8809,3126,5346,8576,11683,12012,2541,7468,3700,12043,6636,274,7905,1637,11874,8091,6388,2132,3454,5363,11278,8138,4104,3664,6955,7423,9252,5243,717,9654,11089,2662,5813,2725,3997,7882,8147,1972,5360,9958,6537,9866,1837,9724,2515,6909,11077,7382,8940,10578,66,991,11249,12078,5661,297,4236,5240,10615,8894,6752,1599,8903,4789,8794,721,143,708,3893,9853,10975,12240,4519,3983,9215,420,8767,11835,10220,3914,10930,3539,11989,4395,2901,1427,7668,5489,4941,6674,12249,5831,3530,12171,10261,775,894,11564,5706,3810,11670,9294,9899,5872,9997,9218,8757,7970,11087,3323,4779,9473,12172,9576,2989,1404,11193,376,7670,9520,11007,10252,55,8952,3523,8081,2097,6848,11377,6165,5777,12044,12000,8941,1892,8951,4426,8954,9118,4116,7340,10060,9311,7351,11995,9476,6246,2151,1574,4104,12141,880,3709,2410,8871,1771,8281,11433,8802,5517,7260,8932,2340,11134,8858,1110,2811,6777,10364,9649,7387,1996,6561,7065,2190,12094,11677,10503,2145,11418,10041,9467,109,5395,5299,7200,11203,3966,6117,1065,3458,5521,12182,6969,1134,7108,648,285,8703,100,12113,6653,7377,6804,1717,9467,10055,4009,3545,7482,28,4253,47,12043,7057,1286,10754,3347,3280,3738,3323,7715,6500,350,12245,11148,1705,6450,336,2873,176,9059,2491,7546,2877,7417,9768,2526,2893,551,9462,1754,3452,7819,10010,844,4087,8473,5019,9155,12253,8338,10746,6837,9485,7469,4277,8497,10631,2810,5104,5895,7050,298,1144,3489,7210,11509,4913,7844,1396,9705,11371,1646,3089,7918,12187,6710,106,6810,3783,9423,180,3100,228,6112,9775,3407,10474,3340,232,11654,454,2551,6891,10879,2473,6594,9791,6870,5661,5877,8893,3075,4752,1135,3859,2495,5101,1384,5825,5539,1734,4694,7444,8731,4653,7432,7238,9267,1719,9790,6698,6049,2948,4962,8614,2381,2866,6384,11786,775,4155,7072,9670,2011,4684,6722,1077,7784,7614,217,90,9505,4379,1799,1159,6056,11386,5041,3383,102,12112,9520,8228,9636,668,210,4688,3381,2281,2261,11425,7820,2252,9565,7195,8650,7037,11164,9071,1220,1974,6262,8288,4926,1069,206,7288,4139,4020,728,10582,10621,4568,5054,9984,6837,236,7164,9106,9007,3765,700,4173,1524,11782,6690,9860,2926,538,11340,6889,10459,7255,7705,6244,10579,7541,10909,11397,9092,115,2610,5294,10509,3454,4985,2496];
        uint256[] memory pk = new uint256[](512);
        for (uint256 i = 0; i < 512; i++) {
            pk[i] = tmp_pk[i];
        }
        // signature s2
        // forgefmt: disable-next-line
        uint[512] memory tmp_s2 = [uint(12283), 12027,24,37,12231,12278,12178,254,12158,12196,12133,12161,12236,12100,12277,164,109,12181,12230,149,12042,11905,12126,12019,515,129,296,12254,12225,119,12080,13,12236,53,12140,293,12253,12283,114,236,12097,119,12193,11905,12112,161,397,281,22,12115,52,12043,39,27,11960,12118,28,12039,87,12177,51,12173,205,4,37,136,12238,67,12239,11846,12177,167,198,12109,12173,167,12147,12233,10,12062,12154,90,10,275,44,12273,27,23,12164,12184,12273,12277,12170,12128,24,63,12119,11907,12028,12146,75,12275,247,12148,141,12254,12134,187,3,12125,12162,50,12225,202,12059,115,48,202,12254,12169,63,160,12162,48,12222,12175,12274,186,323,12273,11963,333,234,102,70,422,40,12143,56,12184,146,54,11959,12170,12132,12215,12201,237,12249,234,48,168,12279,11931,12010,12079,12046,12205,12143,3,36,52,294,4,12049,12255,86,12084,67,60,101,12168,217,12069,101,12130,177,12191,40,164,158,12193,12081,12022,12198,108,77,78,12201,33,237,12176,12016,12275,12178,37,12205,12255,12141,42,12238,35,12091,12275,139,197,12153,89,60,12173,20,12182,12254,156,12054,117,12164,12179,12136,207,13,12189,12255,47,133,12066,327,12104,40,33,12136,12182,12208,154,160,12120,269,28,281,200,12132,12224,136,12265,12068,171,12245,12177,12177,25,12280,101,149,332,74,12255,43,85,58,194,106,12026,49,34,374,231,12276,13,192,91,12004,46,186,12279,369,92,238,12004,12288,12187,12114,245,291,228,89,12255,12050,12174,78,12148,205,87,344,140,12153,134,175,12270,120,12268,12099,12088,12224,12173,12164,11868,76,12002,12084,12102,406,110,70,104,69,315,148,110,274,12116,222,11876,12246,273,47,54,12267,180,12064,139,12134,12170,206,12135,12270,85,12160,58,12265,12013,280,12226,12207,12264,12266,15,12149,158,386,97,11940,12259,294,168,146,11963,242,91,11996,168,11970,12120,12099,12263,184,11983,56,12161,36,12166,12246,12014,12225,12048,20,12239,202,12198,117,351,12115,12090,12191,12280,12203,175,105,12168,12115,173,41,12084,193,258,12205,452,108,12224,12287,12250,167,64,235,185,88,12259,155,11988,40,12177,12170,12186,149,45,12109,229,189,235,177,12140,12118,21,12230,12186,1,234,38,189,12277,12274,12240,42,12207,12076,12051,157,124,12253,12257,130,11804,12246,12263,136,12184,94,104,22,124,12267,12234,29,204,12120,12144,12234,12273,221,12273,181,71,12161,72,98,12187,12183,286,12011,12181,34,12244,12112,206,62,12246,46,12075,69,12028,12267,12247,11957,12061,12157,12069,12032,12041,12258,12013,39,244,12261,57,91,117,12270,12210,12164,12283,218,12271,12228,214,12237,12248,12280,395,12127,12,140,37,40];
        ZKNOX_falcon.Signature memory sig;
        for (uint256 i = 0; i < 512; i++) {
            sig.s2[i] = tmp_s2[i];
        }
        // message
        bytes memory message = "My name is Renaud";
        sig.salt =
            "\x35\x00\x31\x8f\x75\xad\x20\xf0\xaa\x20\x62\xba\x1c\x34\x8a\xfe\xaa\x49\x23\x87\xa4\x63\xeb\x8c\x28\xaf\x77\x9d\x6a\x3e\xa6\x96\xeb\xb9\x66\x0c\xcf\xf5\x06\x2d";
        bool result = falcon.verify(message, sig, pk, true);
        assertEq(true, result);
    }

    function testVector1() public view {
        // public key
        // forgefmt: disable-next-line
        uint[512] memory tmp_pk = [uint(8494), 9875,5391,1879,708,7214,6161,7426,130,4397,5498,8631,2407,9977,1931,7029,2352,991,9225,9158,8285,955,12093,4942,2664,778,3383,11334,11105,10565,3474,7022,2706,1183,6455,1113,1385,4181,5984,1364,6193,7574,2703,11943,2783,9363,10213,6442,10177,6408,8584,2766,1171,7190,253,3679,2625,7796,8043,5703,2065,459,1063,5107,475,7421,2950,1363,9991,2222,1222,2148,12181,10486,7239,2220,8612,10147,11233,10557,3816,7607,2043,9737,1487,6402,7156,4425,11155,8706,2669,9984,4688,8809,3126,5346,8576,11683,12012,2541,7468,3700,12043,6636,274,7905,1637,11874,8091,6388,2132,3454,5363,11278,8138,4104,3664,6955,7423,9252,5243,717,9654,11089,2662,5813,2725,3997,7882,8147,1972,5360,9958,6537,9866,1837,9724,2515,6909,11077,7382,8940,10578,66,991,11249,12078,5661,297,4236,5240,10615,8894,6752,1599,8903,4789,8794,721,143,708,3893,9853,10975,12240,4519,3983,9215,420,8767,11835,10220,3914,10930,3539,11989,4395,2901,1427,7668,5489,4941,6674,12249,5831,3530,12171,10261,775,894,11564,5706,3810,11670,9294,9899,5872,9997,9218,8757,7970,11087,3323,4779,9473,12172,9576,2989,1404,11193,376,7670,9520,11007,10252,55,8952,3523,8081,2097,6848,11377,6165,5777,12044,12000,8941,1892,8951,4426,8954,9118,4116,7340,10060,9311,7351,11995,9476,6246,2151,1574,4104,12141,880,3709,2410,8871,1771,8281,11433,8802,5517,7260,8932,2340,11134,8858,1110,2811,6777,10364,9649,7387,1996,6561,7065,2190,12094,11677,10503,2145,11418,10041,9467,109,5395,5299,7200,11203,3966,6117,1065,3458,5521,12182,6969,1134,7108,648,285,8703,100,12113,6653,7377,6804,1717,9467,10055,4009,3545,7482,28,4253,47,12043,7057,1286,10754,3347,3280,3738,3323,7715,6500,350,12245,11148,1705,6450,336,2873,176,9059,2491,7546,2877,7417,9768,2526,2893,551,9462,1754,3452,7819,10010,844,4087,8473,5019,9155,12253,8338,10746,6837,9485,7469,4277,8497,10631,2810,5104,5895,7050,298,1144,3489,7210,11509,4913,7844,1396,9705,11371,1646,3089,7918,12187,6710,106,6810,3783,9423,180,3100,228,6112,9775,3407,10474,3340,232,11654,454,2551,6891,10879,2473,6594,9791,6870,5661,5877,8893,3075,4752,1135,3859,2495,5101,1384,5825,5539,1734,4694,7444,8731,4653,7432,7238,9267,1719,9790,6698,6049,2948,4962,8614,2381,2866,6384,11786,775,4155,7072,9670,2011,4684,6722,1077,7784,7614,217,90,9505,4379,1799,1159,6056,11386,5041,3383,102,12112,9520,8228,9636,668,210,4688,3381,2281,2261,11425,7820,2252,9565,7195,8650,7037,11164,9071,1220,1974,6262,8288,4926,1069,206,7288,4139,4020,728,10582,10621,4568,5054,9984,6837,236,7164,9106,9007,3765,700,4173,1524,11782,6690,9860,2926,538,11340,6889,10459,7255,7705,6244,10579,7541,10909,11397,9092,115,2610,5294,10509,3454,4985,2496];
        uint256[] memory pk = new uint256[](512);
        for (uint256 i = 0; i < 512; i++) {
            pk[i] = tmp_pk[i];
        }
        // signature s2
        // forgefmt: disable-next-line
        uint[512] memory tmp_s2 = [uint(93), 81,11880,193,12261,12051,12091,126,12187,12264,12122,12074,12074,65,97,12277,224,75,302,109,178,12183,64,70,12265,12174,12205,218,12070,12159,171,90,52,12007,12203,6,12105,369,12021,12165,395,62,126,172,142,26,12228,12228,151,12061,119,12243,12175,12242,71,35,12149,358,84,429,50,12157,12091,82,231,11948,12243,8,12231,12288,12154,12234,12145,13,168,12228,107,12261,130,145,125,136,67,138,58,18,308,12256,130,11999,17,11979,174,12187,12135,12173,12071,12283,12254,12235,58,216,12234,55,12066,12272,228,360,211,12217,31,12101,217,204,76,119,36,334,12197,12283,212,12209,12096,12260,6,43,12174,49,279,63,12231,11846,12150,212,159,147,134,12117,103,20,168,12264,92,129,176,141,12033,220,156,179,10,12174,125,191,0,12202,291,127,11842,12199,9,12097,147,11990,12123,12279,163,103,12160,12177,118,12266,81,68,137,12143,12126,144,11919,12196,98,19,12260,12116,12134,12200,14,52,12211,82,5,20,12121,34,165,12278,12162,12035,152,250,12057,12250,134,106,123,12251,12259,123,12100,12196,195,95,306,12036,63,23,12096,114,197,12121,177,12253,173,12201,166,186,341,12054,26,12082,39,125,168,63,12217,132,12152,12265,225,303,12021,12186,12090,12136,12205,13,86,40,12017,12216,115,12177,12203,12006,12228,12223,347,12213,12228,240,78,70,78,12153,11953,12268,12,12198,158,162,12123,12130,148,12191,12016,12275,12243,12269,71,235,19,12153,12099,12098,12192,38,12259,12117,178,159,12200,117,7,12249,5,12218,12168,172,12152,118,1,12198,12263,184,12236,12177,160,84,12006,249,146,12150,130,12273,12210,12087,53,77,20,290,68,167,12179,277,12261,2,63,140,11987,297,91,11954,12235,79,104,59,137,1,12253,11845,12186,470,12055,12092,72,12048,17,214,227,12218,12083,12102,150,406,12273,12238,12110,99,54,11984,167,12059,12087,76,12265,204,12078,12157,12192,11893,12284,12054,11996,12183,12133,56,29,33,100,237,12277,12261,12065,12214,12281,12068,0,12254,12195,11880,12262,12247,12246,413,12209,12169,243,158,12076,211,240,12089,140,8,90,12224,12107,143,155,12234,12265,45,12131,12111,12269,222,12026,95,122,127,12151,119,337,12134,12251,87,12242,21,46,12260,9,158,109,12127,12285,12255,51,100,12116,12207,11962,12277,311,88,96,39,12151,12116,156,12089,12125,12068,12183,12278,396,82,11928,12224,12128,27,11922,12257,12218,12213,12169,277,2,12159,102,442,90,12064,25,12274,224,12128,12052,12224,12061,162,12020,61,93,12063,12241,118,12067,153,12197,12257,12283,218,125,12072,12167,63,12268,32,86,12145,237,75,251,12261,12216,5,12213,12279,97,11937,12095,12088];
        ZKNOX_falcon.Signature memory sig;
        for (uint256 i = 0; i < 512; i++) {
            sig.s2[i] = tmp_s2[i];
        }
        // message
        bytes memory message = "My name is Simon";
        sig.salt =
            "\xdb\xae\x77\x2d\xb2\x90\x58\xa8\x8f\x9b\xd8\x30\xe9\x57\xc6\x95\x34\x7c\x41\xb6\x16\x2a\x7e\xb9\xa9\xea\x13\xde\xf3\x4b\xe5\x6b\x8b\xbb\xb9\x64\xb3\x23\xd7\x67";
        bool result = falcon.verify(message, sig, pk, true);
        assertEq(true, result);
    }

    function testVector2() public view {
        // public key
        // forgefmt: disable-next-line
        uint[512] memory tmp_pk = [uint(8494), 9875,5391,1879,708,7214,6161,7426,130,4397,5498,8631,2407,9977,1931,7029,2352,991,9225,9158,8285,955,12093,4942,2664,778,3383,11334,11105,10565,3474,7022,2706,1183,6455,1113,1385,4181,5984,1364,6193,7574,2703,11943,2783,9363,10213,6442,10177,6408,8584,2766,1171,7190,253,3679,2625,7796,8043,5703,2065,459,1063,5107,475,7421,2950,1363,9991,2222,1222,2148,12181,10486,7239,2220,8612,10147,11233,10557,3816,7607,2043,9737,1487,6402,7156,4425,11155,8706,2669,9984,4688,8809,3126,5346,8576,11683,12012,2541,7468,3700,12043,6636,274,7905,1637,11874,8091,6388,2132,3454,5363,11278,8138,4104,3664,6955,7423,9252,5243,717,9654,11089,2662,5813,2725,3997,7882,8147,1972,5360,9958,6537,9866,1837,9724,2515,6909,11077,7382,8940,10578,66,991,11249,12078,5661,297,4236,5240,10615,8894,6752,1599,8903,4789,8794,721,143,708,3893,9853,10975,12240,4519,3983,9215,420,8767,11835,10220,3914,10930,3539,11989,4395,2901,1427,7668,5489,4941,6674,12249,5831,3530,12171,10261,775,894,11564,5706,3810,11670,9294,9899,5872,9997,9218,8757,7970,11087,3323,4779,9473,12172,9576,2989,1404,11193,376,7670,9520,11007,10252,55,8952,3523,8081,2097,6848,11377,6165,5777,12044,12000,8941,1892,8951,4426,8954,9118,4116,7340,10060,9311,7351,11995,9476,6246,2151,1574,4104,12141,880,3709,2410,8871,1771,8281,11433,8802,5517,7260,8932,2340,11134,8858,1110,2811,6777,10364,9649,7387,1996,6561,7065,2190,12094,11677,10503,2145,11418,10041,9467,109,5395,5299,7200,11203,3966,6117,1065,3458,5521,12182,6969,1134,7108,648,285,8703,100,12113,6653,7377,6804,1717,9467,10055,4009,3545,7482,28,4253,47,12043,7057,1286,10754,3347,3280,3738,3323,7715,6500,350,12245,11148,1705,6450,336,2873,176,9059,2491,7546,2877,7417,9768,2526,2893,551,9462,1754,3452,7819,10010,844,4087,8473,5019,9155,12253,8338,10746,6837,9485,7469,4277,8497,10631,2810,5104,5895,7050,298,1144,3489,7210,11509,4913,7844,1396,9705,11371,1646,3089,7918,12187,6710,106,6810,3783,9423,180,3100,228,6112,9775,3407,10474,3340,232,11654,454,2551,6891,10879,2473,6594,9791,6870,5661,5877,8893,3075,4752,1135,3859,2495,5101,1384,5825,5539,1734,4694,7444,8731,4653,7432,7238,9267,1719,9790,6698,6049,2948,4962,8614,2381,2866,6384,11786,775,4155,7072,9670,2011,4684,6722,1077,7784,7614,217,90,9505,4379,1799,1159,6056,11386,5041,3383,102,12112,9520,8228,9636,668,210,4688,3381,2281,2261,11425,7820,2252,9565,7195,8650,7037,11164,9071,1220,1974,6262,8288,4926,1069,206,7288,4139,4020,728,10582,10621,4568,5054,9984,6837,236,7164,9106,9007,3765,700,4173,1524,11782,6690,9860,2926,538,11340,6889,10459,7255,7705,6244,10579,7541,10909,11397,9092,115,2610,5294,10509,3454,4985,2496];
        uint256[] memory pk = new uint256[](512);
        for (uint256 i = 0; i < 512; i++) {
            pk[i] = tmp_pk[i];
        }
        // signature s2
        // forgefmt: disable-next-line
        uint[512] memory tmp_s2 = [uint(168), 12128,15,12280,12060,12287,12278,36,207,154,12239,12185,12041,12245,11949,59,339,119,206,51,233,33,12189,146,4,57,12232,12200,12287,48,12177,12116,12161,71,12198,341,42,179,12201,84,342,12068,440,265,12253,70,31,12161,11918,445,53,12020,12228,12096,12027,12248,12240,12188,11957,186,12221,12276,12191,241,109,50,12273,12282,65,92,94,12286,11975,220,12078,124,185,509,58,57,104,80,12045,124,12243,12121,11832,125,290,12267,67,12197,12108,119,12257,287,12208,12248,12115,70,12180,11950,12053,12132,12268,372,45,223,12220,132,8,12046,12256,12046,75,61,193,2,11960,11977,154,203,91,11,12106,16,11969,99,12246,12192,12079,192,12114,12119,88,38,12229,12245,145,12256,12091,12118,195,122,78,12153,12011,12157,12210,12225,291,12104,12146,12269,12244,12107,12246,19,52,89,125,76,12089,59,12022,7,12248,46,12217,12169,12233,12267,273,12284,14,11957,78,117,12099,12250,135,9,12193,46,12214,11932,12143,18,12277,40,12247,18,101,35,137,94,12094,50,3,106,165,118,42,12147,253,11954,12144,12123,12142,239,368,12085,67,12210,12033,12095,11957,12147,152,72,12117,7,12135,12238,12197,330,12121,12219,123,14,12260,45,12179,183,12258,27,12143,12120,12036,12158,0,12226,12243,5,12280,6,12067,92,12116,12236,179,246,12229,12125,12202,63,12280,170,12182,113,12077,12277,43,12237,12043,90,147,12022,12147,38,12257,13,12226,12186,12264,12257,13,12002,138,12254,12272,12092,47,27,120,44,12211,12226,11910,12266,12258,205,12173,56,12225,12202,123,12146,12174,192,12279,208,89,12199,12150,169,12097,12204,48,95,146,299,355,36,10,12242,80,12023,12185,339,144,191,202,12286,12065,54,12252,11964,11956,11988,393,11891,70,12241,77,7,189,12263,12091,100,23,12204,12163,21,15,207,11,12272,12091,12144,12263,12212,12287,12141,22,12130,12129,12270,94,3,12256,0,292,12143,12138,66,241,61,23,105,69,12095,12246,7,179,12208,12265,3,115,505,12238,12200,70,40,12257,12181,36,12175,56,106,118,28,258,93,47,12153,28,27,12208,115,384,12097,145,100,104,127,12213,12276,163,12106,203,60,12113,12282,12221,12143,12239,12288,12167,193,12198,52,12123,12022,12280,126,470,12227,145,12178,12190,324,116,105,12189,193,12057,12204,12209,12087,12209,3,20,79,226,11718,105,12056,12249,12227,12270,12256,377,93,12206,12161,12250,156,48,38,187,12138,125,11989,255,12127,75,164,60,39,267,40,129,312,12214,12058,221,12268,12201,65,11830,129,12187,156,12271,164,276,11962,561,57,12158,345,12273,12087,50,95,32,12083,12241,55,127,233,12177,12267,258,12000,61,12139,11989,12249,48,12203];
        ZKNOX_falcon.Signature memory sig;
        for (uint256 i = 0; i < 512; i++) {
            sig.s2[i] = tmp_s2[i];
        }
        // message
        bytes memory message = "My name is Nicolas";
        sig.salt =
            "\x6a\xf1\xf6\x92\xe9\x49\x6c\x6d\x0b\x66\x83\x16\xec\xcb\x93\x27\x6a\xe6\xb6\x77\x4f\xa7\x28\xaa\xc3\x1f\xf4\x0a\x38\x31\x87\x60\xba\x53\x0a\xf5\xf0\x89\x98\x14";
        bool result = falcon.verify(message, sig, pk, true);
        assertEq(true, result);
    }

    function testVector3() public view {
        // public key
        // forgefmt: disable-next-line
        uint[512] memory tmp_pk = [uint(8494), 9875,5391,1879,708,7214,6161,7426,130,4397,5498,8631,2407,9977,1931,7029,2352,991,9225,9158,8285,955,12093,4942,2664,778,3383,11334,11105,10565,3474,7022,2706,1183,6455,1113,1385,4181,5984,1364,6193,7574,2703,11943,2783,9363,10213,6442,10177,6408,8584,2766,1171,7190,253,3679,2625,7796,8043,5703,2065,459,1063,5107,475,7421,2950,1363,9991,2222,1222,2148,12181,10486,7239,2220,8612,10147,11233,10557,3816,7607,2043,9737,1487,6402,7156,4425,11155,8706,2669,9984,4688,8809,3126,5346,8576,11683,12012,2541,7468,3700,12043,6636,274,7905,1637,11874,8091,6388,2132,3454,5363,11278,8138,4104,3664,6955,7423,9252,5243,717,9654,11089,2662,5813,2725,3997,7882,8147,1972,5360,9958,6537,9866,1837,9724,2515,6909,11077,7382,8940,10578,66,991,11249,12078,5661,297,4236,5240,10615,8894,6752,1599,8903,4789,8794,721,143,708,3893,9853,10975,12240,4519,3983,9215,420,8767,11835,10220,3914,10930,3539,11989,4395,2901,1427,7668,5489,4941,6674,12249,5831,3530,12171,10261,775,894,11564,5706,3810,11670,9294,9899,5872,9997,9218,8757,7970,11087,3323,4779,9473,12172,9576,2989,1404,11193,376,7670,9520,11007,10252,55,8952,3523,8081,2097,6848,11377,6165,5777,12044,12000,8941,1892,8951,4426,8954,9118,4116,7340,10060,9311,7351,11995,9476,6246,2151,1574,4104,12141,880,3709,2410,8871,1771,8281,11433,8802,5517,7260,8932,2340,11134,8858,1110,2811,6777,10364,9649,7387,1996,6561,7065,2190,12094,11677,10503,2145,11418,10041,9467,109,5395,5299,7200,11203,3966,6117,1065,3458,5521,12182,6969,1134,7108,648,285,8703,100,12113,6653,7377,6804,1717,9467,10055,4009,3545,7482,28,4253,47,12043,7057,1286,10754,3347,3280,3738,3323,7715,6500,350,12245,11148,1705,6450,336,2873,176,9059,2491,7546,2877,7417,9768,2526,2893,551,9462,1754,3452,7819,10010,844,4087,8473,5019,9155,12253,8338,10746,6837,9485,7469,4277,8497,10631,2810,5104,5895,7050,298,1144,3489,7210,11509,4913,7844,1396,9705,11371,1646,3089,7918,12187,6710,106,6810,3783,9423,180,3100,228,6112,9775,3407,10474,3340,232,11654,454,2551,6891,10879,2473,6594,9791,6870,5661,5877,8893,3075,4752,1135,3859,2495,5101,1384,5825,5539,1734,4694,7444,8731,4653,7432,7238,9267,1719,9790,6698,6049,2948,4962,8614,2381,2866,6384,11786,775,4155,7072,9670,2011,4684,6722,1077,7784,7614,217,90,9505,4379,1799,1159,6056,11386,5041,3383,102,12112,9520,8228,9636,668,210,4688,3381,2281,2261,11425,7820,2252,9565,7195,8650,7037,11164,9071,1220,1974,6262,8288,4926,1069,206,7288,4139,4020,728,10582,10621,4568,5054,9984,6837,236,7164,9106,9007,3765,700,4173,1524,11782,6690,9860,2926,538,11340,6889,10459,7255,7705,6244,10579,7541,10909,11397,9092,115,2610,5294,10509,3454,4985,2496];
        uint256[] memory pk = new uint256[](512);
        for (uint256 i = 0; i < 512; i++) {
            pk[i] = tmp_pk[i];
        }
        // signature s2
        // forgefmt: disable-next-line
        uint[512] memory tmp_s2 = [uint(51), 12262,233,34,12078,12065,44,134,12066,294,11973,12212,4,12188,88,12266,12175,12206,26,12,12102,11959,12053,221,12087,12208,12111,192,108,163,12086,12244,12215,77,12246,12082,12150,72,12105,12045,12254,257,98,12172,12279,164,179,126,144,12175,12207,24,189,12130,109,135,12243,36,81,367,12117,106,12215,12103,172,12274,172,154,279,12287,12195,70,3,11956,12236,141,12280,215,12274,12134,95,12233,101,12192,113,63,12204,12097,42,351,12237,128,33,12083,12074,193,12221,12212,7,12149,94,177,12190,12125,12156,12237,63,44,12060,12171,12135,12257,12003,243,131,12236,12270,114,12243,62,12271,34,17,32,12251,42,118,12149,300,5,12039,12238,12199,193,294,12223,12216,12218,471,49,483,12124,232,65,36,126,12270,12197,39,11897,48,91,158,12138,12239,12097,123,293,81,12270,209,73,12254,12132,12247,12185,208,12237,12236,257,12058,42,59,366,12197,12220,305,12202,12171,12179,233,61,61,12040,137,12277,12252,12172,117,106,12287,12112,12217,255,12167,11890,162,184,26,122,12260,169,7,12204,12245,65,12263,12067,12065,12129,12257,65,12175,127,12201,63,127,84,12248,5,12194,12134,158,502,62,12218,49,12181,232,153,12230,12166,172,171,12252,12243,44,60,119,12091,12092,179,151,12165,93,258,417,12052,12253,12249,42,267,12109,12099,12081,152,12203,223,7,12072,73,32,25,12238,161,12220,212,12275,116,74,12218,12288,135,101,12186,126,12175,65,12248,100,12252,149,35,12149,358,36,12279,94,19,12281,12155,37,12183,201,12048,41,3,12154,70,12209,12136,129,12272,50,408,19,12172,168,12191,25,153,12184,12184,12188,12241,249,12120,154,11991,11967,12153,12150,97,172,23,12060,84,12245,12205,155,11979,12194,16,49,12152,117,116,176,12275,101,12137,12204,392,37,12064,101,12133,12258,198,238,227,12104,84,12203,3,12236,12108,12225,11883,12051,12070,44,12245,199,255,12089,148,198,12216,12236,117,37,500,311,30,199,11988,12188,12108,125,72,12170,12195,46,174,12083,12178,32,12102,12275,117,12191,84,15,121,98,12069,188,219,23,12184,139,176,12250,88,12222,241,231,12240,70,12117,41,64,12202,12236,152,47,48,10,154,474,12236,12027,93,12011,184,131,12104,53,7,12223,113,12242,12261,81,12270,212,12080,20,12078,312,41,47,12197,12214,12156,11940,449,12169,225,12135,12140,11902,12034,74,252,10,12214,11945,92,12257,12236,12048,127,11975,12,11846,54,12062,12277,22,24,191,56,240,12251,181,12021,12090,12267,12123,11957,15,12088,184,186,203,12003,142,255,199,12256,12280,174,38,155,12268,12174,12282,12285,12013,187,26,288,12276,12098,115,12074,191,12288,300,375];
        ZKNOX_falcon.Signature memory sig;
        for (uint256 i = 0; i < 512; i++) {
            sig.s2[i] = tmp_s2[i];
        }
        // message
        bytes memory message = "We are ZKNox";
        sig.salt =
            "\x96\x44\x29\x4a\xc4\xff\xb3\x09\x1e\xef\x01\x21\x9b\x3f\xe4\xfe\x46\x7f\x05\x89\x0c\xc5\x6a\xf9\x61\xdc\xe6\x8f\xdd\xbb\x77\x04\x71\x91\x37\x3e\xdc\x7d\xa9\x43";
        bool result = falcon.verify(message, sig, pk, true);
        assertEq(true, result);
    }
}
