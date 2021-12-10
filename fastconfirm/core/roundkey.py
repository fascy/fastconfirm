import string
import random

from gevent import time

from crypto.ecdsa import ecdsa
from crypto.ecdsa.ecdsa import ecdsa_sign, ecdsa_vrfy
from honeybadgerbft.core.reliablebroadcast import merkleTree, getMerkleBranch, merkleVerify

pks = []
sks = []
pk_mt = []


def round_key_tree(pks, key_num):
    pk_list = [pks[i].format() for i in range(key_num)]
    pk_mt = merkleTree(pk_list)
    pk_root = pk_mt[1]
    # print("publish", pk_root)
    return pk_mt


def round_key_generation(key_num):
    pkrs, skrs = ecdsa.pki(key_num)
    pk_mt = round_key_tree(pkrs, key_num)
    return pkrs, skrs, pk_mt


def sign(sk, msg, mt, position):
    sig = ecdsa_sign(sk, msg)
    branch = getMerkleBranch(position, mt)
    return sig, branch


def vrify(sig, branch, msg, pk, root, position, key_num):
    if ecdsa_vrfy(pk, msg, sig) == True:
        if merkleVerify(key_num, pk.format(), root, branch, position) == True:
            return True
        else:
            return False
    else:
        return False


def tx_generator(size=250, chars=string.ascii_uppercase + string.digits):
    return '<Dummy TX: ' + ''.join(random.choice(chars) for _ in range(size - 10)) + '>'


if __name__ == "__main__":
    """"
    msg = tx_generator(1024)
    pk_mt = round_key_tree(pks, 1024)
    sig_start = time.time()
    sig = ecdsa_sign(sks[1], msg)
    branch = getMerkleBranch(1, pk_mt)
    sig_end = time.time()
    print("Sign time:", sig_end - sig_start)

    v_start = time.time()
    if ecdsa_vrfy(pks[1], msg, sig) == True and merkleVerify(1024, pks[1].format(), pk_mt[1], branch, 1) == True:
        print("VALID")
    v_end = time.time()
    print("Verify time:", v_end - v_start)
    """

    msg = "hello"
    pkrs, skrs, pk_mt = round_key_generation(16)
    sig = sign(skrs[1], msg, pk_mt, 1)
    (s, b) = sig
    print(b)
    if vrify(s, b, msg, pkrs[1], pk_mt[1], 1, 16):
        print("yes")

