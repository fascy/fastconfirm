import hashlib
import pickle

from fastconfirm.core.memselect import memselection
from fastconfirm.core.roundkey import sign


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

def blockproposal(pid, sid, N, PK2s, SK2, rpk, rsk, rmt, round, state, height, lB, hconfirm, input, send, logger=None):
    # lB means the block on the self.height

    def proposal_broadcast(o):
        """SPBC send operation.
        :param o: Value to send.
        """
        # print("node", pid, "is sending", o[0], "to node", k, "with the leader", j)
        for i in range(N):
            send(i, o)

    t, pi, h = memselection(round, 1, PK2s[pid], SK2)
    if t == 1:
        print(pid, "is select!")
        (b, r, s) = state
        txs = input()
        if s == 2:
            position = ((round - 1) * 4) + 0
            Block = (hash(lB), txs)
            sig = sign(rsk[position], str(Block), rmt, position)
            # todo: add omega
            height += 1
            msg = (2, h, pi, Block, hash(Block), height, sig)

        if s == 1:
            position = ((round - 1) * 4) + 0
            Block = (hash(lB), txs)
            sig = sign(rsk[position], str(Block), rmt, position)
            height += 1
            msg = (1, h, pi, (Block, lB), (hash(Block), hash(lB)), height, sig)

        if s == 0:
            position = ((round - 1) * 4) + 0
            Block = (hconfirm, txs)
            sig = sign(rsk[position], str(Block), rmt, position)
            msg = (0, h, pi, Block, hash(Block), height, sig)

        proposal_broadcast(msg)
        # print(pid, "sends", msg)
        return 1
    else:
        print(pid, "is not selected as a committee member")
        return 0
