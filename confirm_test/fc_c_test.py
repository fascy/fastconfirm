import random
import time
import gevent
from gevent import monkey
from gevent.queue import Queue

from crypto.ecdsa import ecdsa
from crypto.threshsig.generate_keys import dealer
from crypto.threshenc import tpke
from fastconfirm.core.fastconfirm import Fastconfirm

monkey.patch_all(thread=False)


def simple_router(N, maxdelay=0.01, seed=None):
    """Builds a set of connected channels, with random delay

    :return: (receives, sends)
    """
    rnd = random.Random(seed)

    queues = [Queue() for _ in range(N)]
    _threads = []

    def makeSend(i):
        def _send(j, o):
            delay = rnd.random() * maxdelay
            if not i % 3:
                delay *= 0
            gevent.spawn_later(delay, queues[j].put_nowait, (i, o))

        return _send

    def makeRecv(j):
        def _recv():
            (i, o) = queues[j].get()
            # print(j, (i, o))
            # print 'RECV %8s [%2d -> %2d]' % (o[0], i, j)
            return (i, o)

        return _recv

    return ([makeSend(i) for i in range(N)],
            [makeRecv(j) for j in range(N)])


### Test asynchronous common subset
def _test_dumbo(N=8, f=2, seed=None):
    sid = 'sidA'
    pks, sks = ecdsa.pki(N)

    rnd = random.Random(seed)
    # print 'SEED:', seed
    router_seed = rnd.random()
    sends, recvs = simple_router(N, seed=router_seed)

    fcs = [None] * N
    threads = [None] * N

    # This is an experiment parameter to specify the maximum round number
    K = 10
    B = 10
    S = 10

    for i in range(N):
        fcs[i] = Fastconfirm(sid, i, S, B, N, f, pks, sks[i],
                          sends[i], recvs[i], K)
        # print(sPK, sSKs[i], ePK, eSKs[i])

    for i in range(N):
        # if i == 1: continue
        fcs[i].round_key_gen(1024)

    for i in range(N):
        threads[i] = gevent.spawn(fcs[i].run_fast)

    print('start the test...')
    time_start = time.time()

    # gevent.killall(threads[N-f:])
    # gevent.sleep(3)
    # for i in range(N-f, N):
    #    inputs[i].put(0)
    try:
        outs = [threads[i].get() for i in range(N)]
        print(outs)
        # Consistency check
        assert len(set(outs)) == 1
    except KeyboardInterrupt:
        gevent.killall(threads)
        raise

    time_end = time.time()
    print('complete the test...')
    print('time cost: ', time_end - time_start, 's')


def test_dumbo():
    _test_dumbo()


if __name__ == '__main__':
    test_dumbo()
