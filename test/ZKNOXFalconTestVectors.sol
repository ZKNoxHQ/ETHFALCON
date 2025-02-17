// code generated using pythonref/generate_falcon_test_vectors.py.
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
        uint[512] memory tmp_s2 = [uint(12189), 253,12275,406,12187,59,285,152,12257,165,12227,26,8,85,12137,12164,122,232,12110,118,149,12008,12286,12272,64,199,76,12237,12280,335,129,24,12251,137,12251,38,250,12245,12176,12048,109,35,173,404,12127,12088,3,206,325,222,299,147,190,182,152,12049,12264,46,173,112,168,114,12180,12282,114,12092,89,12215,12173,12160,186,21,12131,84,12189,12249,12207,39,63,172,93,12194,19,12252,12160,15,12140,4,396,12105,12219,153,12237,12043,12228,12245,269,12034,92,353,12256,12196,38,130,12240,12051,12154,12255,202,12160,12263,12251,123,41,12033,12079,69,12263,17,34,12278,12231,12265,12153,106,67,17,136,12256,15,12204,12185,12087,276,12112,12210,61,23,12152,12136,97,12272,6,12126,156,12127,12211,12091,104,12034,12254,67,12022,12260,12141,12244,276,66,12158,263,12158,11982,26,112,154,12288,64,12021,128,44,12257,128,12205,12288,12277,11956,11745,11940,12126,12240,12122,12181,12170,12064,279,12092,12194,126,108,141,395,4,12036,12257,12203,95,12089,12252,120,12214,12244,12272,130,12230,12123,12197,12122,60,12245,213,173,47,239,145,12090,12128,12157,12017,307,75,120,12205,12187,153,12190,12180,22,76,12007,121,12228,94,20,12148,79,51,12019,83,182,427,12203,63,40,216,12180,12093,12106,88,143,208,160,28,273,193,12205,89,196,12167,278,12243,12175,12249,12168,11958,12143,12165,12106,12272,89,336,18,58,12277,147,79,149,12266,81,12219,21,12202,12284,12179,12037,12106,339,11895,107,12112,12059,2,12265,208,355,361,12047,31,304,114,12217,12116,80,202,12055,12188,52,125,12258,12071,12237,12081,12041,12165,180,12128,85,327,12018,327,44,12246,51,135,33,12255,24,5,67,12089,12219,12097,12277,12181,12106,92,73,12272,12195,100,12033,12281,187,185,31,11963,12281,71,84,416,12186,12202,12157,12178,141,13,143,95,12068,12086,234,12209,40,12261,12074,12132,323,17,131,60,12074,12091,12060,133,43,12119,12180,83,12195,12263,11902,12192,12213,38,12278,508,12148,12217,62,12260,12171,162,44,11974,12133,83,12165,12225,50,12237,49,12221,149,12144,87,39,35,35,12279,12164,149,182,130,12258,167,11981,12193,12058,12081,95,318,170,12220,102,146,208,275,83,237,82,12247,12182,12233,60,12252,304,12033,12221,167,121,12152,82,11927,12099,12151,12206,89,12209,183,30,12283,78,12239,12111,12224,232,12272,12093,111,152,105,109,14,12248,12035,1,12003,165,225,12129,197,70,99,293,11985,26,12148,12183,12076,12134,129,12191,12279,12024,12006,17,12181,215,518,128,12256,12100,26,276,12185,15,41,12280,12128,102,269,231,12037,12094,96,134,12027,12125,12215,310,12065,12170,12034];
        ZKNOX_falcon.Signature memory sig;
        for (uint256 i = 0; i < 512; i++) {
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
        uint[512] memory tmp_pk = [uint(8494), 9875,5391,1879,708,7214,6161,7426,130,4397,5498,8631,2407,9977,1931,7029,2352,991,9225,9158,8285,955,12093,4942,2664,778,3383,11334,11105,10565,3474,7022,2706,1183,6455,1113,1385,4181,5984,1364,6193,7574,2703,11943,2783,9363,10213,6442,10177,6408,8584,2766,1171,7190,253,3679,2625,7796,8043,5703,2065,459,1063,5107,475,7421,2950,1363,9991,2222,1222,2148,12181,10486,7239,2220,8612,10147,11233,10557,3816,7607,2043,9737,1487,6402,7156,4425,11155,8706,2669,9984,4688,8809,3126,5346,8576,11683,12012,2541,7468,3700,12043,6636,274,7905,1637,11874,8091,6388,2132,3454,5363,11278,8138,4104,3664,6955,7423,9252,5243,717,9654,11089,2662,5813,2725,3997,7882,8147,1972,5360,9958,6537,9866,1837,9724,2515,6909,11077,7382,8940,10578,66,991,11249,12078,5661,297,4236,5240,10615,8894,6752,1599,8903,4789,8794,721,143,708,3893,9853,10975,12240,4519,3983,9215,420,8767,11835,10220,3914,10930,3539,11989,4395,2901,1427,7668,5489,4941,6674,12249,5831,3530,12171,10261,775,894,11564,5706,3810,11670,9294,9899,5872,9997,9218,8757,7970,11087,3323,4779,9473,12172,9576,2989,1404,11193,376,7670,9520,11007,10252,55,8952,3523,8081,2097,6848,11377,6165,5777,12044,12000,8941,1892,8951,4426,8954,9118,4116,7340,10060,9311,7351,11995,9476,6246,2151,1574,4104,12141,880,3709,2410,8871,1771,8281,11433,8802,5517,7260,8932,2340,11134,8858,1110,2811,6777,10364,9649,7387,1996,6561,7065,2190,12094,11677,10503,2145,11418,10041,9467,109,5395,5299,7200,11203,3966,6117,1065,3458,5521,12182,6969,1134,7108,648,285,8703,100,12113,6653,7377,6804,1717,9467,10055,4009,3545,7482,28,4253,47,12043,7057,1286,10754,3347,3280,3738,3323,7715,6500,350,12245,11148,1705,6450,336,2873,176,9059,2491,7546,2877,7417,9768,2526,2893,551,9462,1754,3452,7819,10010,844,4087,8473,5019,9155,12253,8338,10746,6837,9485,7469,4277,8497,10631,2810,5104,5895,7050,298,1144,3489,7210,11509,4913,7844,1396,9705,11371,1646,3089,7918,12187,6710,106,6810,3783,9423,180,3100,228,6112,9775,3407,10474,3340,232,11654,454,2551,6891,10879,2473,6594,9791,6870,5661,5877,8893,3075,4752,1135,3859,2495,5101,1384,5825,5539,1734,4694,7444,8731,4653,7432,7238,9267,1719,9790,6698,6049,2948,4962,8614,2381,2866,6384,11786,775,4155,7072,9670,2011,4684,6722,1077,7784,7614,217,90,9505,4379,1799,1159,6056,11386,5041,3383,102,12112,9520,8228,9636,668,210,4688,3381,2281,2261,11425,7820,2252,9565,7195,8650,7037,11164,9071,1220,1974,6262,8288,4926,1069,206,7288,4139,4020,728,10582,10621,4568,5054,9984,6837,236,7164,9106,9007,3765,700,4173,1524,11782,6690,9860,2926,538,11340,6889,10459,7255,7705,6244,10579,7541,10909,11397,9092,115,2610,5294,10509,3454,4985,2496];
        uint256[] memory pk = new uint256[](512);
        for (uint256 i = 0; i < 512; i++) {
            pk[i] = tmp_pk[i];
        }
        // signature s2
        // forgefmt: disable-next-line
        uint[512] memory tmp_s2 = [uint(244), 12128,12021,12098,12064,289,12200,110,12235,220,12111,386,40,12187,145,12195,11826,47,216,119,178,12279,12164,62,135,121,152,12284,225,11950,12232,12139,69,235,12265,134,12020,12006,12090,50,139,12133,12248,196,12156,12256,12,12222,102,12212,44,12089,261,12059,12261,318,132,134,56,12278,56,79,12199,111,12219,329,12209,39,12234,415,12146,77,12063,29,51,143,157,12111,126,57,50,11976,127,70,12125,11952,12161,12252,11937,294,12118,11944,12203,131,87,12246,369,349,12285,12231,12136,12276,129,330,12060,12228,137,65,189,12286,12194,12208,139,12150,74,15,67,12137,100,39,40,12238,318,63,11944,5,12072,12172,12158,114,159,12220,12273,11970,12236,12032,12189,57,135,66,12228,12280,147,20,12083,12200,133,12233,12149,12160,12087,12055,12144,12211,27,12251,424,637,12286,107,12050,12190,12128,12058,130,61,371,12035,42,12023,80,157,12096,82,203,12240,179,12260,12245,310,72,94,105,113,170,11926,12254,167,102,181,198,12173,33,2,204,12189,12171,191,93,12072,99,10,12265,12103,68,12134,12247,69,131,12178,12215,119,11993,296,36,142,12166,182,12238,12253,39,12272,12147,206,183,365,48,44,194,12249,117,12251,81,155,12162,86,12074,12221,12067,12255,12001,12250,99,74,12235,114,205,168,11981,12014,12199,115,100,12,12268,135,9,12144,12281,43,2,261,48,12194,12236,220,90,73,12203,72,12141,12246,12260,12237,12080,37,50,75,12199,35,214,12078,12084,12,11915,11829,48,125,163,12095,185,193,122,63,107,234,12108,12023,12125,12073,12129,12227,12275,12183,148,11989,11974,12162,47,379,12174,12234,11995,12130,12160,12274,12260,62,12083,12093,86,56,12075,12235,12174,12147,11953,81,12072,102,12110,11947,89,226,137,180,12,12127,12013,12205,12010,38,12268,12238,12230,12112,12062,12263,12234,184,168,12158,220,12181,178,40,24,377,11,125,103,226,14,12225,12226,224,12134,210,53,11742,116,119,12232,12214,12158,12166,12174,272,31,12,60,1,21,145,314,12288,188,12000,42,47,12230,259,12152,12214,12259,357,47,36,266,12211,12172,114,180,130,12264,12274,12204,69,210,151,12223,86,12263,183,12037,12215,101,12137,12142,12133,12206,78,257,12229,149,342,26,288,13,12222,12151,11890,12187,20,24,12285,12171,13,12230,212,12192,197,12178,87,11888,102,12269,12241,12097,44,12098,90,24,43,298,12204,3,11929,12268,52,51,12172,12134,192,12178,218,20,12178,96,155,12172,181,322,11,163,12194,12288,117,12080,35,11922,169,209,87,171,12207,4,12090,12205,73,12078,12170,12022,194,12209,12122,26,95,12263,11991,12015,313,12002,12040,183,242,94,122,36,12215,193,12238];
        ZKNOX_falcon.Signature memory sig;
        for (uint256 i = 0; i < 512; i++) {
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
        uint[512] memory tmp_pk = [uint(8494), 9875,5391,1879,708,7214,6161,7426,130,4397,5498,8631,2407,9977,1931,7029,2352,991,9225,9158,8285,955,12093,4942,2664,778,3383,11334,11105,10565,3474,7022,2706,1183,6455,1113,1385,4181,5984,1364,6193,7574,2703,11943,2783,9363,10213,6442,10177,6408,8584,2766,1171,7190,253,3679,2625,7796,8043,5703,2065,459,1063,5107,475,7421,2950,1363,9991,2222,1222,2148,12181,10486,7239,2220,8612,10147,11233,10557,3816,7607,2043,9737,1487,6402,7156,4425,11155,8706,2669,9984,4688,8809,3126,5346,8576,11683,12012,2541,7468,3700,12043,6636,274,7905,1637,11874,8091,6388,2132,3454,5363,11278,8138,4104,3664,6955,7423,9252,5243,717,9654,11089,2662,5813,2725,3997,7882,8147,1972,5360,9958,6537,9866,1837,9724,2515,6909,11077,7382,8940,10578,66,991,11249,12078,5661,297,4236,5240,10615,8894,6752,1599,8903,4789,8794,721,143,708,3893,9853,10975,12240,4519,3983,9215,420,8767,11835,10220,3914,10930,3539,11989,4395,2901,1427,7668,5489,4941,6674,12249,5831,3530,12171,10261,775,894,11564,5706,3810,11670,9294,9899,5872,9997,9218,8757,7970,11087,3323,4779,9473,12172,9576,2989,1404,11193,376,7670,9520,11007,10252,55,8952,3523,8081,2097,6848,11377,6165,5777,12044,12000,8941,1892,8951,4426,8954,9118,4116,7340,10060,9311,7351,11995,9476,6246,2151,1574,4104,12141,880,3709,2410,8871,1771,8281,11433,8802,5517,7260,8932,2340,11134,8858,1110,2811,6777,10364,9649,7387,1996,6561,7065,2190,12094,11677,10503,2145,11418,10041,9467,109,5395,5299,7200,11203,3966,6117,1065,3458,5521,12182,6969,1134,7108,648,285,8703,100,12113,6653,7377,6804,1717,9467,10055,4009,3545,7482,28,4253,47,12043,7057,1286,10754,3347,3280,3738,3323,7715,6500,350,12245,11148,1705,6450,336,2873,176,9059,2491,7546,2877,7417,9768,2526,2893,551,9462,1754,3452,7819,10010,844,4087,8473,5019,9155,12253,8338,10746,6837,9485,7469,4277,8497,10631,2810,5104,5895,7050,298,1144,3489,7210,11509,4913,7844,1396,9705,11371,1646,3089,7918,12187,6710,106,6810,3783,9423,180,3100,228,6112,9775,3407,10474,3340,232,11654,454,2551,6891,10879,2473,6594,9791,6870,5661,5877,8893,3075,4752,1135,3859,2495,5101,1384,5825,5539,1734,4694,7444,8731,4653,7432,7238,9267,1719,9790,6698,6049,2948,4962,8614,2381,2866,6384,11786,775,4155,7072,9670,2011,4684,6722,1077,7784,7614,217,90,9505,4379,1799,1159,6056,11386,5041,3383,102,12112,9520,8228,9636,668,210,4688,3381,2281,2261,11425,7820,2252,9565,7195,8650,7037,11164,9071,1220,1974,6262,8288,4926,1069,206,7288,4139,4020,728,10582,10621,4568,5054,9984,6837,236,7164,9106,9007,3765,700,4173,1524,11782,6690,9860,2926,538,11340,6889,10459,7255,7705,6244,10579,7541,10909,11397,9092,115,2610,5294,10509,3454,4985,2496];
        uint256[] memory pk = new uint256[](512);
        for (uint256 i = 0; i < 512; i++) {
            pk[i] = tmp_pk[i];
        }
        // signature s2
        // forgefmt: disable-next-line
        uint[512] memory tmp_s2 = [uint(12188), 12192,11965,138,12168,12028,4,12130,231,12199,12168,12078,12119,258,17,335,12226,12273,12164,12138,12192,12109,105,132,12072,4,5,12206,11947,12262,12030,120,12274,373,12219,12273,12176,12219,173,12140,155,12273,12177,64,12238,12255,24,12113,12228,12113,142,101,12206,11965,11959,12182,127,12242,178,313,74,136,15,398,11721,266,44,5,12173,201,101,12112,29,237,12235,12238,11895,11992,12092,12271,59,185,50,12219,12131,306,12141,12093,12242,11902,12177,27,94,12064,12102,12131,12141,167,12283,12096,12223,155,53,228,49,120,395,325,12270,232,91,12,75,11988,391,67,18,81,12166,12096,23,12233,91,12231,414,114,140,12247,165,79,12284,13,12187,12280,192,112,347,119,30,87,171,12178,11815,91,12037,12212,12226,12085,12197,12185,12234,78,39,59,76,31,12186,133,8,305,12062,125,12213,41,12274,128,12170,215,212,275,97,193,102,213,42,216,37,12114,95,193,227,12202,212,111,12093,48,172,12262,12268,12053,12208,56,12139,122,12184,12187,14,12086,32,12224,12153,12214,12021,12264,12282,77,178,12215,16,12256,23,284,19,16,12254,107,62,12265,12278,35,12001,12281,12102,116,257,337,12235,12219,11,132,11961,247,81,10,100,45,12232,12261,30,360,12040,12074,12263,29,12271,69,232,11953,125,73,47,12158,210,67,12134,38,12284,12124,36,12268,464,12281,281,12143,12117,113,12164,247,274,280,12170,12254,12269,12282,12025,12272,12275,12213,12202,29,12269,12196,69,11903,194,188,266,141,12075,389,12101,12133,12095,165,134,399,61,12220,12205,224,49,12103,305,12282,53,12003,12007,239,103,41,11998,12267,12175,135,171,164,53,211,180,1,12277,113,11995,318,12205,12172,12174,90,194,12177,175,11927,170,12149,12150,12165,12197,11963,84,45,127,12135,362,12136,153,12115,12267,34,169,12248,94,29,140,105,12157,86,307,181,12197,12102,133,158,12101,176,12238,12118,12160,12079,149,12048,114,12275,12186,132,57,12215,12161,316,11999,123,99,12166,243,12202,12170,12131,92,208,12246,12255,3,12259,106,132,60,12150,85,15,96,12184,12115,296,12262,12155,12003,12208,12238,12285,105,12258,86,147,12216,12239,46,12099,6,12252,11989,8,12211,58,12,16,12199,382,129,120,12235,12209,12283,12161,12169,11930,12188,12120,55,256,128,12264,12124,29,12078,116,12175,117,12238,12200,12283,10,12162,116,329,162,239,12055,116,12210,12287,12155,0,58,12226,12233,12222,11994,284,12066,247,12222,12150,12128,158,145,12224,114,12238,12272,116,24,117,12229,28,12178,12187,366,12043,98,12096,22,125,12083,77,12077,12075,133,259,37,24,12041,12168,12164,235,12207,191,12250,208,12221,12279,13,47,12205];
        ZKNOX_falcon.Signature memory sig;
        for (uint256 i = 0; i < 512; i++) {
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
        uint[512] memory tmp_pk = [uint(8494), 9875,5391,1879,708,7214,6161,7426,130,4397,5498,8631,2407,9977,1931,7029,2352,991,9225,9158,8285,955,12093,4942,2664,778,3383,11334,11105,10565,3474,7022,2706,1183,6455,1113,1385,4181,5984,1364,6193,7574,2703,11943,2783,9363,10213,6442,10177,6408,8584,2766,1171,7190,253,3679,2625,7796,8043,5703,2065,459,1063,5107,475,7421,2950,1363,9991,2222,1222,2148,12181,10486,7239,2220,8612,10147,11233,10557,3816,7607,2043,9737,1487,6402,7156,4425,11155,8706,2669,9984,4688,8809,3126,5346,8576,11683,12012,2541,7468,3700,12043,6636,274,7905,1637,11874,8091,6388,2132,3454,5363,11278,8138,4104,3664,6955,7423,9252,5243,717,9654,11089,2662,5813,2725,3997,7882,8147,1972,5360,9958,6537,9866,1837,9724,2515,6909,11077,7382,8940,10578,66,991,11249,12078,5661,297,4236,5240,10615,8894,6752,1599,8903,4789,8794,721,143,708,3893,9853,10975,12240,4519,3983,9215,420,8767,11835,10220,3914,10930,3539,11989,4395,2901,1427,7668,5489,4941,6674,12249,5831,3530,12171,10261,775,894,11564,5706,3810,11670,9294,9899,5872,9997,9218,8757,7970,11087,3323,4779,9473,12172,9576,2989,1404,11193,376,7670,9520,11007,10252,55,8952,3523,8081,2097,6848,11377,6165,5777,12044,12000,8941,1892,8951,4426,8954,9118,4116,7340,10060,9311,7351,11995,9476,6246,2151,1574,4104,12141,880,3709,2410,8871,1771,8281,11433,8802,5517,7260,8932,2340,11134,8858,1110,2811,6777,10364,9649,7387,1996,6561,7065,2190,12094,11677,10503,2145,11418,10041,9467,109,5395,5299,7200,11203,3966,6117,1065,3458,5521,12182,6969,1134,7108,648,285,8703,100,12113,6653,7377,6804,1717,9467,10055,4009,3545,7482,28,4253,47,12043,7057,1286,10754,3347,3280,3738,3323,7715,6500,350,12245,11148,1705,6450,336,2873,176,9059,2491,7546,2877,7417,9768,2526,2893,551,9462,1754,3452,7819,10010,844,4087,8473,5019,9155,12253,8338,10746,6837,9485,7469,4277,8497,10631,2810,5104,5895,7050,298,1144,3489,7210,11509,4913,7844,1396,9705,11371,1646,3089,7918,12187,6710,106,6810,3783,9423,180,3100,228,6112,9775,3407,10474,3340,232,11654,454,2551,6891,10879,2473,6594,9791,6870,5661,5877,8893,3075,4752,1135,3859,2495,5101,1384,5825,5539,1734,4694,7444,8731,4653,7432,7238,9267,1719,9790,6698,6049,2948,4962,8614,2381,2866,6384,11786,775,4155,7072,9670,2011,4684,6722,1077,7784,7614,217,90,9505,4379,1799,1159,6056,11386,5041,3383,102,12112,9520,8228,9636,668,210,4688,3381,2281,2261,11425,7820,2252,9565,7195,8650,7037,11164,9071,1220,1974,6262,8288,4926,1069,206,7288,4139,4020,728,10582,10621,4568,5054,9984,6837,236,7164,9106,9007,3765,700,4173,1524,11782,6690,9860,2926,538,11340,6889,10459,7255,7705,6244,10579,7541,10909,11397,9092,115,2610,5294,10509,3454,4985,2496];
        uint256[] memory pk = new uint256[](512);
        for (uint256 i = 0; i < 512; i++) {
            pk[i] = tmp_pk[i];
        }
        // signature s2
        // forgefmt: disable-next-line
        uint[512] memory tmp_s2 = [uint(660), 29,49,104,60,185,183,122,12149,70,89,11915,193,102,140,192,227,12172,12194,12233,225,12104,100,55,1,39,196,12283,259,147,12162,12256,12250,12175,165,12206,59,67,62,12239,12271,284,12252,11946,12162,97,319,12233,12091,12271,12073,11929,12187,80,195,12120,12245,12179,1,131,12178,12102,12168,87,132,162,12,111,12253,12171,320,113,166,97,63,12157,101,70,12051,12075,42,12175,12195,12110,224,12033,254,12250,12240,11999,336,58,90,12180,258,12212,288,151,12242,12285,30,12026,11,48,161,52,12221,12053,12156,126,350,13,149,58,12024,12285,47,12007,12211,12234,65,12214,11863,12203,11981,6,219,354,261,114,12194,12151,49,12123,12188,77,113,292,12202,187,148,11949,187,24,112,12180,155,12213,31,44,12252,12019,12239,12286,80,12248,202,12189,85,12281,12228,265,12168,12277,183,131,440,11943,197,12188,63,71,12235,247,12195,12255,12251,12127,12014,12261,12220,78,213,26,138,12017,254,12258,12260,197,2,12228,70,245,12218,12213,249,208,12235,11988,216,11961,11954,45,12052,58,13,12214,12210,273,8,79,65,44,12023,12288,278,121,12067,12134,17,12070,12225,69,143,35,12105,198,11933,12135,12281,10,209,74,239,12235,248,122,12113,40,12203,12065,12073,242,251,3,161,12270,12083,15,37,253,133,12129,181,12020,54,178,188,86,12199,232,12079,12186,12281,98,12213,256,12228,12191,12256,33,35,12047,12256,122,56,12234,121,12121,143,158,12287,12209,12153,98,12098,143,12239,316,165,12212,178,60,24,107,12117,207,165,12217,12194,99,12172,16,38,12164,100,105,12228,12120,162,77,12137,62,256,12266,10,20,11996,11907,12073,213,183,111,103,12212,12232,12141,284,226,9,335,12154,301,254,12039,12146,54,12266,123,12175,142,12278,12154,84,12210,12250,31,102,12079,408,12246,155,12060,12026,48,93,12144,205,12207,320,12168,12267,134,12136,34,1,249,32,31,12243,12177,12121,39,21,12203,12284,133,102,103,12223,12249,12258,11956,12010,19,65,12082,12149,12189,27,83,12102,62,97,264,12273,92,11967,29,12287,12155,6,33,327,5,11,55,12130,12240,128,254,4,12243,108,12282,12102,12085,220,242,73,12195,12165,12131,93,165,12070,107,12212,34,12184,156,12250,11988,38,12190,12199,11899,12159,12245,12262,12125,26,12222,313,43,93,143,64,319,12200,207,12049,150,12153,26,12230,12213,282,12235,582,219,12138,12158,12283,12047,12053,12167,79,41,250,97,189,76,75,141,202,12224,107,26,12244,59,12202,12241,68,81,12211,43,8,12288,18,12158,12122,340,270,9,12159,365,44,351,189,32,132,12175,12025,233,12205,12197,12214,12098,12265,11999];
        ZKNOX_falcon.Signature memory sig;
        for (uint256 i = 0; i < 512; i++) {
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
