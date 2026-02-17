gauss_1024_12289 = [
    1283868770400643928, 6416574995475331444, 4078260278032692663,
    2353523259288686585, 1227179971273316331,  575931623374121527,
     242543240509105209,   91437049221049666,   30799446349977173,
       9255276791179340,    2478152334826140,     590642893610164,
        125206034929641,      23590435911403,       3948334035941,
           586753615614,        77391054539,          9056793210,
              940121950,           86539696,             7062824,
                 510971,              32764,               1862,
                     94,                  4,                  0,
]

def get_rng_u64(randombytes):
    tmp = randombytes(8)
    return int.from_bytes(tmp, "little")

def mkgauss(rng, logn):
    g = 1 << (10 - logn)
    val = 0
    for _ in range(g):
        r = get_rng_u64(rng)
        neg = r >> 63
        r &= ~(1 << 63)
        f = (r - gauss_1024_12289[0]) >> 63 & 1

        v = 0
        r = get_rng_u64(rng)
        r &= ~(1 << 63)
        for k in range(1, len(gauss_1024_12289)):
            t = ((r - gauss_1024_12289[k]) >> 63 & 1) ^ 1
            v |= k & -(t & (f ^ 1))
            f |= t

        v = (v ^ (-neg & 0xFFFFFFFF)) + neg
        v = v & 0xFFFFFFFF
        if v >= 0x80000000:
            v -= 0x100000000
        val += v
    return val

def poly_small_mkgauss(rng, n, logn):
    f = [0] * n
    mod2 = 0
    for u in range(n):
        while True:
            s = mkgauss(rng, logn)
            if s < -127 or s > 127:
                continue
            if u == n - 1:
                if (mod2 ^ (s & 1)) == 0:
                    continue
            else:
                mod2 ^= (s & 1)
            break
        f[u] = s
    return f