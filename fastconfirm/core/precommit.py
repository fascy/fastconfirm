import hashlib
import pickle

from fastconfirm.core.memselect import memselection
from fastconfirm.core.roundkey import sign


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def precommit(pid, sid, N, PK2s, SK2, rpk, rsk, rmt, round, t, pi, h, c, voteset, pc_hB, send, logger=None):
    # lB means the block on the self.height

    def pre_broadcast(o):
        """SPBC send operation.
        :param o: Value to send.
        """
        # print("node", pid, "is sending", o[0], "to node", k, "with the leader", j)
        for i in range(N):
            send(i, o)

    # print("--", pid, h, pi)
    if t == 1:
        print(pid, "is select in commit!")

        if c > 0:
            position = ((round - 1) * 4) + 2
            sig = sign(rsk[position], str(voteset) + str(pc_hB), rmt, position)
            msg = (1, h, pi, pc_hB, voteset, sig)

        if c == 0:
            # not a valid C
            position = ((round - 1) * 4) + 2
            sig = sign(rsk[position], "null", rmt, position)
            msg = (0, h, pi, None, None, sig)

        pre_broadcast(msg)
        # print(pid, "sends", msg)
        return 1
    else:
        print(pid, "is not selected as a committee member")
        return 0
