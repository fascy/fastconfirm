from crypto.VRF import VRF_prove, VRF_verifying
from crypto.ecdsa import ecdsa


def memselection(r, s, pk, sk, k=4, T=1):
    threshold = pow(2, (k - 1) * 8)*(1 - T)
    pi, h = VRF_prove(pk, sk,str(r)+str(s), k)
    if int.from_bytes(h, 'big') > threshold:
        # print("selected!")
        return 1, pi, h
    else:
        return 0, pi, h

def vrifymember(r, s, h, pi, pk, k=4, T=1):
    threshold = pow(2, (k - 1) * 8) * (1 - T)
    if VRF_verifying(pk, pi, h, str(r)+str(s), k):
        if int.from_bytes(h, 'big') > threshold:
            return True
        else: return False
    else:
        return False


if __name__ == "__main__":
    vrflist =[(0, 0, 0)] * 100
    pk, sk = ecdsa.pki(100)
    count = 0
    for i in range(100):
        public_key = pk[i]
        private_key = sk[i]
        (t, pi, h) = memselection(1, 1, public_key, private_key)
        vrflist[i] = (t, pi, h)
    for i in range(100):
        print(vrflist[i])
    i = 0
    for i in range(100):
        public_key = pk[i]
        (t, pi, h) = vrflist[i]
        print(vrifymember(1, 1, h, pi, public_key))
