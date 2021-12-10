import random

import gevent
from gevent import Greenlet
from gevent.queue import Queue

from crypto.ecdsa import ecdsa
from dumbobft.core.consistentbroadcast import consistentbroadcast


# generate round keys
from fastconfirm.core.blockproposal import blockproposal
from fastconfirm.core.first import fastconfirm
from fastconfirm.core.roundkey import round_key_generation


def round_key_gen(self, key_num):
    self.pk_ts, self.sk_ts, self.pk_mt = round_key_generation(key_num)




# CBC
def simple_router(N, maxdelay=0.01, seed=None):
    """Builds a set of connected channels, with random delay
    @return (receives, sends)
    """
    rnd = random.Random(seed)
    #if seed is not None: print 'ROUTER SEED: %f' % (seed,)

    queues = [Queue() for _ in range(N)]

    def makeSend(i):
        def _send(j, o):
            delay = rnd.random() * maxdelay
            # print ('SEND %8s [%2d -> %2d] %.2f' % (o[0], i, j, delay))
            gevent.spawn_later(delay, queues[j].put, (i, o))
            # print("here", msg)
            #queues[j].put((i, o))
        return _send

    def makeRecv(j):
        def _recv():
            (i, o) = queues[j].get()
            # print('RECV %8s [%2d -> %2d]' % (o[0], i, j))
            return i, o
        return _recv

    return ([makeSend(i) for i in range(N)],
            [makeRecv(j) for j in range(N)])


def _test_bp(N=4, f=1, leader=None, seed=None):
    # Test everything when runs are OK
    sid = 'sidA'
    # Note thld siganture for CBC has a threshold different from common coin's
    pks, sks = ecdsa.pki(4)

    rnd = random.Random(seed)
    router_seed = rnd.random()
    sends, recvs = simple_router(N, seed=seed)

    threads = []
    inputs = [Queue(1) for _ in range(N)]

    for i in range(N):
        inputs[i].put_nowait("Hello! This is a test message from node %d" % i)
        print("Input to node %d has been provided" % i)

    for i in range(N):
        rpk, rsk, rmt = round_key_generation(1024)

        t = Greenlet(fastconfirm, sid, i, N, f, pks, sks[i], inputs[i].get, sends[i], recvs[i])
        t.start()
        threads.append(t)

    gevent.joinall(threads)

def test_cbc(N, f, seed):
    _test_bp(N=N, f=f, seed=seed)


if __name__ == '__main__':
    test_cbc(4, 1, None)
