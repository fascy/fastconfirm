import hashlib
import binascii
import operator
import math
import pickle
import sys
from sys import argv
from gevent import time
from crypto.ecdsa import ecdsa
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def integer_byte_size(n):
    '''Returns the number of bytes necessary to store the integer n.'''
    quanta, mod = divmod(integer_bit_size(n), 8)
    if mod or n == 0:
        quanta += 1
    return quanta

def integer_bit_size(n):
    '''Returns the number of bits necessary to store the integer n.'''
    if n == 0:
        return 1
    s = 0
    while n:
        s += 1
        n >>= 1
    return s

def integer_ceil(a, b):
    '''Return the ceil integer of a div b.'''
    quanta, mod = divmod(a, b)
    if mod:
        quanta += 1
    return quanta

class RsaPublicKey(object):
    __slots__ = ('n', 'e', 'bit_size', 'byte_size')

    def __init__(self, n, e):
        self.n = n
        self.e = e
        self.bit_size = integer_bit_size(n)
        self.byte_size = integer_byte_size(n)

    def __repr__(self):
        return '<RsaPublicKey n: %d e: %d bit_size: %d>' % (self.n, self.e, self.bit_size)

    def rsavp1(self, s):
        if not (0 <= s <= self.n-1):
            raise Exception("s not within 0 and n - 1")
        return self.rsaep(s)

    def rsaep(self, m):
        if not (0 <= m <= self.n-1):
            raise Exception("m not within 0 and n - 1")
        return pow(m, self.e, self.n)

class RsaPrivateKey(object):
    __slots__ = ('n', 'd', 'bit_size', 'byte_size')

    def __init__(self, n, d):
        self.n = n
        self.d = d
        self.bit_size = integer_bit_size(n)
        self.byte_size = integer_byte_size(n)

    def __repr__(self):
        return '<RsaPrivateKey n: %d d: %d bit_size: %d>' % (self.n, self.d, self.bit_size)

    def rsadp(self, c):
        if not (0 <= c <= self.n-1):
            raise Exception("c not within 0 and n - 1")
        return pow(c, self.d, self.n)

    def rsasp1(self, m):
        if not (0 <= m <= self.n-1):
            raise Exception("m not within 0 and n - 1")
        return self.rsadp(m)

def i2osp(x, x_len):
    '''
    Converts the integer x to its big-endian representation of length
    x_len.
    '''
    # if x > 256**x_len:
    #     raise ValueError("integer too large")
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = binascii.unhexlify(h)
    return b'\x00' * int(x_len-len(x)) + x

def os2ip(x):
    '''
    Converts the byte string x representing an integer reprented using the
    big-endian convient to an integer.
    '''
    h = binascii.hexlify(x)
    return int(h, 16)

def mgf1(mgf_seed, mask_len):
    '''
    Mask Generation Function v1 from the PKCS#1 v2.0 standard.
    mgs_seed - the seed, a byte string
    mask_len - the length of the mask to generate
    Return value: a pseudo-random mask, as a byte string
    '''
    h_len = hashlib.sha256().digest_size
    if mask_len > 0x10000:
        raise ValueError('mask too long')
    T = b''
    for i in range(0, integer_ceil(mask_len, h_len)):
        C = i2osp(i, 4)
        T = T + hash(pickle.dumps(mgf_seed + str(C)))
    return T[:mask_len]

def VRF_prove(public_key, private_key, alpha, k):
    # k is the length of pi
    m = mgf1(alpha+str(public_key), k-1)
    # print("EM:", m, type(m))
    pi = ecdsa_sign(private_key, m)
    # s = private_key.rsasp1(m)
    return pi, m

def VRF_proof2hash(pi):
    beta = hash(pi)
    return beta

def VRF_verifying(public_key, pi, h, alpha, k):
    if ecdsa_vrfy(public_key, h, pi) and mgf1(alpha+str(public_key), k-1) == h:
        return True
    else:
        return False

if __name__ == "__main__":
    pk, sk = ecdsa.pki(1000)
    k = 4
    T = pow(2, (k - 1) * 8)*(1 - 0.685)
    print(T)
    count = 0
    for i in range (1000):

        public_key = pk[i]
        private_key = sk[i]

        alpha = "1"
        pi, h = VRF_prove(public_key, private_key, alpha, k)
        print("h is",int.from_bytes(h, 'big'))
        if int.from_bytes(h, 'big') > T:
            count += 1
        #beta = VRF_proof2hash(pi)
        #start = time.time()
        print(VRF_verifying(public_key, pi, h, alpha, k))
        #end = time.time()
        #print((end - start))
    print(count)