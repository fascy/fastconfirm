import hashlib
import pickle

from fastconfirm.core.memselect import memselection
from fastconfirm.core.roundkey import sign


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

def vote(pid, sid, N, PK2s, SK2, rpk, rsk, rmt, round, t, pi, h, leadermsg, send, logger=None):
    # lB means the block on the self.height

    def vote_broadcast(o):
        """SPBC send operation.
        :param o: Value to send.
        """
        # print("node", pid, "is sending", o[0], "to node", k, "with the leader", j)
        for i in range(N):
            send(i, o)

    # print("--", pid, h, pi)
    if t == 1:
        print(pid, "is select in vote!")
        (g, hl, pil, B, hB, height, sig) = leadermsg

        if g > 0:
            position = ((round - 1) * 4) + 1
            sig = sign(rsk[position], str(hB), rmt, position)
            msg = (1, h, pi, hB, height, sig)

        if g == 0:
            position = ((round - 1) * 4) + 1
            sig = sign(rsk[position], str(hB), rmt, position)
            msg = (0, h, pi, hB, height, sig)

        vote_broadcast(msg)
        # print(pid, "sends", msg)
        return 1
    else:
        print(pid, "is not selected as a committee member")
        return 0
