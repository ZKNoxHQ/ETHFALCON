from falcon import SecretKey
from falcon_epervier import EpervierSecretKey
from falcon_recovery import RecoveryModeSecretKey
from scripts.sign_KAT import sign_KAT
from timeit import default_timer as timer


class BenchSignature():
    def bench_recovery_epervier(self):
        print("Verification time")
        print("n\tFalcon\t\tFalconRec\tEpervier")
        for n in [64, 128, 256, 512, 1024]:
            print(n, end='\t')
            iterations = 100
            f = sign_KAT[n][0]["f"]
            g = sign_KAT[n][0]["g"]
            F = sign_KAT[n][0]["F"]
            G = sign_KAT[n][0]["G"]
            message = b"abc"
            # Falcon
            sk = SecretKey(n, [f, g, F, G])
            sig = sk.sign(message)
            assert sk.verify(message, sig)
            t00 = timer()
            for i in range(iterations):
                sk.verify(message, sig)
            t0 = timer()
            print("{:.1f}ms".format(
                (t0-t00)/iterations * 10**3),
                end='\t\t'
            )
            # Falcon Rec
            sk = RecoveryModeSecretKey(n, [f, g, F, G])
            sig = sk.sign(message)
            pk = sk.pk
            assert pk == sk.recover(message, sig)
            t1 = timer()
            for i in range(iterations):
                sk.recover(message, sig)
            t2 = timer()
            print("{:.1f}ms".format(
                (t2-t1)/iterations * 10**3),
                end='\t\t'
            )
            # Epervier
            sk = EpervierSecretKey(n, [f, g, F, G])
            sig = sk.sign(message)
            pk = sk.pk
            assert pk == sk.recover(message, sig)
            t3 = timer()
            for i in range(iterations):
                sk.recover(message, sig)
            t4 = timer()
            print("{:.1f}ms".format(
                (t4-t3)/iterations * 10**3)
            )


B = BenchSignature()
B.bench_recovery_epervier()
