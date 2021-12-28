from gevent import monkey;

from fastconfirm.core.blockproposal import blockproposal
from fastconfirm.core.commit import commit
from fastconfirm.core.memselect import memselection, vrifymember
from fastconfirm.core.precommit import precommit
from fastconfirm.core.roundkey import round_key_generation, sign, vrify
from fastconfirm.core.vote import vote

monkey.patch_all(thread=False)

import hashlib
import pickle
from crypto.ecdsa.ecdsa import ecdsa_vrfy

import json
import logging
import os
import traceback, time
import gevent
import numpy as np
from collections import namedtuple, defaultdict
from enum import Enum
from gevent import Greenlet
from gevent.queue import Queue
from honeybadgerbft.core.honeybadger_block import honeybadger_block
from honeybadgerbft.exceptions import UnknownTagError


def set_consensus_log(id: int):
    logger = logging.getLogger("consensus-node-" + str(id))
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/log')
    full_path = os.path.realpath(os.getcwd()) + '/log/' + "consensus-node-" + str(id) + ".log"
    file_handler = logging.FileHandler(full_path)
    file_handler.setFormatter(formatter)  # 可以通过setFormatter指定输出格式
    logger.addHandler(file_handler)
    return logger


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


class BroadcastTag(Enum):
    F_BP = 'F_BP'
    F_VOTE = 'F_VOTE'
    F_PC = 'F_PC'
    F_COMMIT = 'F_COMMIT'


BroadcastReceiverQueues = namedtuple(
    'BroadcastReceiverQueues', ('F_BP', 'F_VOTE', 'F_PC', 'F_COMMIT'))


def broadcast_receiver_loop(recv_func, recv_queues):
    while True:
        sender, (tag, msg) = recv_func()
        # print("recv:", sender, tag, msg)
        if tag not in BroadcastTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, BroadcastTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]

        # if tag == BroadcastTag.X_NWABC.value:
        # recv_queue = recv_queue[r]
        try:
            recv_queue.put_nowait((sender, msg))
            # print("receiver_loop:", sender, "->", pid, msg)
        except AttributeError as e:
            print("error", sender, (tag, msg))
            traceback.print_exc(e)


class Fastconfirm:
    def __init__(self, sid, pid, S, B, N, f, sPK2s, sSK2, send, recv, K=3, mute=False,
                 debug=False):

        self.sid = sid
        self.id = pid
        self.SLOTS_NUM = S
        self.N = N
        self.f = f
        self.sPK2s = sPK2s
        self.sSK2 = sSK2
        self._send = send
        self._recv = recv
        self.logger = set_consensus_log(pid)
        self.transaction_buffer = gevent.queue.Queue()
        # self.output_list = defaultdict(lambda: Queue())

        self.K = K
        self.debug = debug

        self.s_time = 0
        self.e_time = 0
        self.tx_cnt = 0
        self.txcnt = 0
        self.txdelay = 0

        self.mute = mute
        self.threads = []
        self.round = 1
        self._tobe_commit = Queue()
        self.state = (0, 0, 0)  # b, r, g
        self.lastcommit = 0
        self.height = 0
        self.lB = None
        self.hconfirm = hash(self.lB)
        self.T = 1
        self.input = Queue(1)

        self.rpk = [] * 1024
        self.rsk = [] * 1024
        self.pk_root = 0
        self.rmt = None

        self._per_round_recv = {}

    # generate round keys
    def round_key_gen(self, key_num):
        self.rpk, self.rsk, self.rmt = round_key_generation(key_num)

    def fastconfirm_round(self):
        bp_recvs = Queue()
        vote_recvs = Queue()
        pc_recvs = Queue()
        commit_recvs = Queue()

        recv_queues = BroadcastReceiverQueues(
            F_BP=bp_recvs,
            F_VOTE=vote_recvs,
            F_PC=pc_recvs,
            F_COMMIT=commit_recvs
        )
        recv_loop_thred = Greenlet(broadcast_receiver_loop, self._per_round_recv[self.round].get, recv_queues)
        recv_loop_thred.start()

        while self.input.empty() is not True:
            self.input.get()
        self.input.put("this is a tx batch in round " + str(self.round))

        def make_bp_send(r):  # this make will automatically deep copy the enclosed send func
            def bp_send(k, o):
                """CBC send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                # print("node", self.id, "is sending", o[0], "to node", k, "with the round", r)
                self._send(k, ('F_BP', r, o))

            return bp_send

        # generate round keys
        # rpk, rsk, rmt = round_key_generation(1024)

        blockproposal(self.id, self.sid + 'BP', self.N, self.sPK2s, self.sSK2, self.rpk, self.rsk, self.rmt, self.round,
                      self.state, self.height, self.lB, self.hconfirm, self.input.get,
                      make_bp_send(self.round))

        def make_vote_send(r):  # this make will automatically deep copy the enclosed send func
            def vote_send(k, o):
                """CBC send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                # print("node", pid, "is sending", o[0], "to node", k, "with the round", r)
                self._send(k, ('F_VOTE', r, o))

            return vote_send

        delta = 0.08
        start = time.time()
        t, my_pi, my_h = memselection(self.round, 2, self.sPK2s[self.id], self.sSK2)
        bp_count = 0
        if t == 1:
            # wait for bp finish
            # print(start)
            (b, r, lg) = self.state
            maxh = 0
            leader = 0
            leader_msg = None
            while time.time() - start < delta:
                gevent.sleep(0)
                # print(bp_recvs.qsize())
            while bp_recvs.qsize() > 0:
                gevent.sleep(0)
                sender, (g, h, pi, B, hB, height, sig) = bp_recvs.get()
                # print(sender, (g, h, pi, B, hB, height, sig))

                if lg == 2 or (lg == 1 and self.lastcommit == 1):
                    if g == 0:
                        continue
                if maxh < int.from_bytes(h, 'big'):
                    maxh = int.from_bytes(h, 'big')
                    leader = sender
                    # print(self.id, "change:", leader)
                    leader_msg = (g, h, pi, B, hB, height, sig)
            # print(self.id, "get the leader:", leader, "chosen block is:", leader_msg)
            vote(self.id, self.sid, self.N, self.sPK2s, self.sSK2, self.rpk, self.rsk, self.rmt,
                 self.round, t, my_pi, my_h, leader_msg, make_vote_send(self.round))
        else:
            while time.time() - start < delta:
                gevent.sleep(0)
            vote(self.id, self.sid, self.N, self.sPK2s, self.sSK2, self.rpk, self.rsk, self.rmt,
                 self.round, t, my_pi, my_h, None, make_vote_send(self.round))

        def make_pc_send(r):  # this make will automatically deep copy the enclosed send func
            def pc_send(k, o):
                """CBC send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                # print("node", pid, "is sending", o[0], "to node", k, "with the round", r)
                self._send(k, ('F_PC', r, o))

            return pc_send

        # wait for vote msg
        t, my_pi, my_h = memselection(self.round, 3, self.sPK2s[self.id], self.sSK2)
        if t == 1:
            voteset = defaultdict(lambda: Queue())
            c = 0
            count = 0
            start = time.time()
            pc_hB = 0
            while time.time() - start < delta:
                gevent.sleep(0)
            while vote_recvs.qsize() > 0:
                gevent.sleep(0)
                sender, (g, h, pi, hB, height, sig) = vote_recvs.get()
                if vrifymember(self.round, 2, h, pi, self.sPK2s[sender]):
                    (s, b) = sig
                    # assert vrify(s, b, hB, sPK2s[sender], rmt, ((round - 1) * 4) + 1, 1024)
                    voteset[hB].put(sig)
                    if voteset[hB].qsize() >= (2 * self.f + 1) * self.T:
                        pc_hB = hB
                        c = 1
            """
            if c == 1:
                print("get a valid vote set")
            else:
                print("not valid vote set")
            """
            precommit(self.id, self.sid, self.N, self.sPK2s, self.sSK2, self.rpk, self.rsk, self.rmt,
                      self.round, t, my_pi, my_h, c, pc_hB,
                      make_pc_send(self.round))
        else:
            while time.time() - start < delta:
                gevent.sleep(0)
            precommit(self.id, self.sid, self.N, self.sPK2s, self.sSK2, self.rpk, self.rsk, self.rmt,
                      self.round, t, my_pi, my_h, 0, None,
                      make_pc_send(self.round))

        def make_commit_send(r):  # this make will automatically deep copy the enclosed send func
            def commit_send(k, o):
                """CBC send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                # print("node", pid, "is sending", o[0], "to node", k, "with the round", r)
                self._send(k, ('F_COMMIT', r, o))

            return commit_send

        # wait for pre-commit finish
        preset = defaultdict(lambda: Queue())
        o = 0
        count = 0
        start = time.time()
        c_hB = 0
        c = 0
        while time.time() - start < delta:
            gevent.sleep(0)
        while pc_recvs.qsize() > 0:
            gevent.sleep(0)
            sender, (g, h, pi, pc_hB, sig) = pc_recvs.get()

            if vrifymember(self.round, 3, h, pi, self.sPK2s[sender]):
                (s, b) = sig
                # assert vrify(s, b, hB, sPK2s[sender], rmt, ((round - 1) * 4) + 1, 1024)
                preset[pc_hB].put((sender, h, pi, sig))
                if preset[pc_hB].qsize() >= (2 * self.f + 1) * self.T:
                    c_hB = pc_hB
                    o = 1
        """
        if o == 1:
            print("get a valid omega set")
        else:
            print("not a valid omega set")
        """
        commit(self.id, self.sid, self.N, self.sPK2s, self.sSK2, self.rpk, self.rsk, self.rmt,
               self.round, o, preset[c_hB], c_hB, make_commit_send(self.round))

        # wait for commit finish
        omegaset = defaultdict(lambda: Queue())
        pc = 0
        count = 0
        start = time.time()
        g_hB = 0
        while time.time() - start < delta:
            try:
                gevent.sleep(0)
                sender, (o_j, h, pi, c_hB_j, omega, sig, rpk_j, rmt_j) = commit_recvs.get_nowait()
            except:
                continue
            if vrifymember(self.round, 4, h, pi, self.sPK2s[sender]):
                (s, b) = sig
                if vrify(s, b, str(omega) + str(c_hB_j), rpk_j, rmt_j, ((self.round - 1) * 4) + 3, 1024):
                    omegaset[c_hB].put((sender, h, pi, omega, sig))
                    if omegaset[c_hB].qsize() >= (2 * self.f + 1) * self.T:
                        g_hB = c_hB
                        pc = 1
        """
        if pc == 1:
            print("get a valid PC set")
        else:
            print("not a valid PC set")
        """
        if c_hB == g_hB:
            self.state = (g_hB, self.round, 2)
        elif (c_hB != g_hB and pc == 1) or (o == 0 and pc == 1):
            self.state = (g_hB, self.round, 1)
        elif o == 0 and pc == 0:
            self.state = (c_hB, self.round, 0)
        # print(self.state)

        if self.round == 1:
            print(B)
        else:
            (h_s, round_s, g_s) = self.state
            if g_s == 2:
                if hash(self.lB) == B[0]:
                    self.height += 1
                    print("output in round ", self.round, B)
                    lastcommit = 1
                    lB = B
                else:
                    while self._tobe_commit.empty() is not True:
                        tB = self._tobe_commit.get()
                        self.height += 1
                        print("output in round ", self.round, tB)
                    self.height += 1
                    print("output in round ", self.round, B)
                    self.lastcommit = 1
                    self.lB = B
            else:
                print("do not have commited block in round ", self.round)
                self.lastcommit = 0
                self._tobe_commit.put(B)
        self.round += 1

    def run_fast(self):
        def _recv_loop():
            """Receive messages."""
            #print("start recv loop...")
            while True:
                #gevent.sleep(0)
                try:
                    sender, (tag, r, msg) = self._recv()
                    # print('recv1' + str((sender, r, msg)))
                    # Maintain an *unbounded* recv queue for each epoch
                    if r not in self._per_round_recv:
                        self._per_round_recv[r] = Queue()
                    # Buffer this message
                    self._per_round_recv[r].put_nowait((sender, (tag, msg)))
                except:
                    continue
        self._recv_thread = Greenlet(_recv_loop)
        self._recv_thread.start()



        while self.round <= self.SLOTS_NUM:
            if self.round not in self._per_round_recv:
                self._per_round_recv[self.round] = Queue()
            st = time.time()
            self.fastconfirm_round()
            if self.id == 0: print(time.time()-st)
            time.sleep(0.1)
