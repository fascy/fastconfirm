import hashlib
import pickle

from fastconfirm.core.memselect import memselection
from fastconfirm.core.roundkey import sign


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def commit(pid, sid, N, PK2s, SK2, rpk, rsk, rmt, round, o, omega, c_hB, send, logger=None):

    def commit_broadcast(o):
        """SPBC send operation.
        :param o: Value to send.
        """
        # print("node", pid, "is sending", o[0], "to node", k, "with the leader", j)
        for i in range(N):
            send(i, o)

    if o > 0:
        position = ((round - 1) * 4) + 3
        sig = sign(rsk[position], str(omega) + str(c_hB), rmt, position)

    if o == 0:
        # not a valid C
        position = ((round - 1) * 4) + 3
        sig = sign(rsk[position], "null", rmt, position)

    t, my_pi, my_h = memselection(round, 4, PK2s[pid], SK2)
    # print("--", pid, h, pi)
    if t == 1:
        print(pid, "is select in pre-commit!")
        msg = (o, my_h, my_pi, c_hB, omega, sig, rpk[position], rmt[1])
        commit_broadcast(msg)
        # print(pid, "sends", msg)
        return 1
    else:
        print(pid, "is not selected as a committee member")
        return 0
