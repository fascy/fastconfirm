from gevent import monkey;

from fastconfirm.core.blockproposal import blockproposal
from fastconfirm.core.commit import commit
from fastconfirm.core.memselect import memselection, vrifymember
from fastconfirm.core.precommit import precommit
from fastconfirm.core.roundkey import round_key_generation, sign, vrify
from fastconfirm.core.vote import vote

monkey.patch_all(thread=False)

import hashlib
import multiprocessing
import pickle
from crypto.ecdsa.ecdsa import ecdsa_vrfy
from dumbobft.core.validatedagreement import validatedagreement
from multiprocessing import Process, Queue

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



class BroadcastTag(Enum):
    F_BP = 'F_BP'
    F_VOTE = 'F_VOTE'
    F_PC = 'F_PC'
    F_COMMIT = 'F_COMMIT'


BroadcastReceiverQueues = namedtuple(
    'BroadcastReceiverQueues', ('F_BP', 'F_VOTE', 'F_PC', 'F_COMMIT'))


def broadcast_receiver_loop(recv_func, recv_queues, pid):
    while True:
        sender, (tag, r, msg) = recv_func()
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
            print("receiver_loop:", sender,  "->", pid, msg)
        except AttributeError as e:
            print("error", sender, (tag, r, msg))
            traceback.print_exc(e)

def fastconfirm(sid, pid, N, f, sPK2s, sSK2, input, send, recv, K=3, debug=False):
    round = 1
    bp_recvs = Queue()
    vote_recvs = Queue()
    pc_recvs = Queue()
    commit_recvs = Queue()
    _tobe_commit = Queue()
    state = (0, 0, 0)  # b, r, g
    lastcommit = 0
    height = 0
    lB = None
    hconfirm = hash(lB)
    T = 1

    recv_queues = BroadcastReceiverQueues(
        F_BP = bp_recvs,
        F_VOTE = vote_recvs,
        F_PC = pc_recvs,
        F_COMMIT = commit_recvs
    )
    recv_loop_thred = Greenlet(broadcast_receiver_loop, recv, recv_queues, pid)
    recv_loop_thred.start()

    def make_bp_send(r):  # this make will automatically deep copy the enclosed send func
        def bp_send(k, o):
            """CBC send operation.
            :param k: Node to send.
            :param o: Value to send.
            """
            # print("node", pid, "is sending", o[0], "to node", k, "with the round", r)
            send(k, ('F_BP', r, o))

        return bp_send

    # generate round keys
    rpk, rsk, rmt = round_key_generation(1024)

    blockproposal(pid, sid+'BP', N, sPK2s, sSK2, rpk, rsk, rmt, round, state, height, lB, hconfirm, input, make_bp_send(round))

    def make_vote_send(r):  # this make will automatically deep copy the enclosed send func
        def vote_send(k, o):
            """CBC send operation.
            :param k: Node to send.
            :param o: Value to send.
            """
            # print("node", pid, "is sending", o[0], "to node", k, "with the round", r)
            send(k, ('F_VOTE', r, o))

        return vote_send

    delta = 0.2
    start = time.time()
    t, my_pi, my_h = memselection(round, 2, sPK2s[pid], sSK2)
    if t == 1:
        #wait for bp finish
        # print(start)
        (b, r, lg) = state
        minh = 0
        leader = 0
        leader_msg = None
        while time.time()-start < delta:
            try:
                gevent.sleep(0)
                sender, (g, h, pi, B, hB, height, sig) = bp_recvs.get_nowait()
            except:
                continue
            if lg == 2 or (lg == 1 and lastcommit == 1):
                if g == 0:
                    continue
            if minh < int.from_bytes(h, 'big'):
                minh = int.from_bytes(h, 'big')
                leader = sender
                # print(pid, "change:", leader)
                leader_msg = (g, h, pi, B, hB, height, sig)
        print(pid, "get the leader:", leader, "chosen block is:", leader_msg)
        vote(pid, sid, N, sPK2s, sSK2, rpk, rsk, rmt, round, t, my_pi, my_h, leader_msg, make_vote_send(round))
    else:
        while time.time() - start < delta:
            gevent.sleep(0)
        vote(pid, sid, N, sPK2s, sSK2, rpk, rsk, rmt, round, t, my_pi, my_h, None, make_vote_send(round))

    def make_pc_send(r):  # this make will automatically deep copy the enclosed send func
        def pc_send(k, o):
            """CBC send operation.
            :param k: Node to send.
            :param o: Value to send.
            """
            # print("node", pid, "is sending", o[0], "to node", k, "with the round", r)
            send(k, ('F_PC', r, o))

        return pc_send

    # wait for vote msg
    t, my_pi, my_h = memselection(round, 3, sPK2s[pid], sSK2)
    if t == 1:
        voteset = defaultdict(lambda: Queue())
        c = 0
        count = 0
        start = time.time()
        pc_hB = 0
        while time.time()-start < delta:
            try:
                gevent.sleep(0)
                sender, (g, h, pi, hB, height, sig) = vote_recvs.get_nowait()
                # print(sender, (g, h, pi, hB, height, sig))
            except:
                continue

            if vrifymember(round, 2, h, pi, sPK2s[sender]):
                (s, b) = sig
                # assert vrify(s, b, hB, sPK2s[sender], rmt, ((round - 1) * 4) + 1, 1024)
                voteset[hB].put(sig)
                if voteset[hB].qsize() >= (2 * f + 1) * T:
                    pc_hB = hB
                    c = 1
        if c == 1:
            print("get a valid vote set")
        else:
            print("not valid vote set")
        precommit(pid, sid, N, sPK2s, sSK2, rpk, rsk, rmt, round,t, my_pi, my_h, c, voteset[pc_hB], pc_hB, make_pc_send(round))
    else:
        while time.time() - start < delta:
            gevent.sleep(0)
        precommit(pid, sid, N, sPK2s, sSK2, rpk, rsk, rmt, round, t, my_pi, my_h, 0, None, None,
                  make_pc_send(round))

    def make_commit_send(r):  # this make will automatically deep copy the enclosed send func
        def commit_send(k, o):
            """CBC send operation.
            :param k: Node to send.
            :param o: Value to send.
            """
            # print("node", pid, "is sending", o[0], "to node", k, "with the round", r)
            send(k, ('F_COMMIT', r, o))

        return commit_send

    # wait for pre-commit finish
    preset = defaultdict(lambda: Queue())
    o = 0
    count = 0
    start = time.time()
    c_hB = 0
    c = 0
    while time.time() - start < delta:
        try:
            gevent.sleep(0)
            sender, (g, h, pi, pc_hB, voteset, sig) = pc_recvs.get_nowait()
        except:
            continue
        if vrifymember(round, 3, h, pi, sPK2s[sender]):
            (s, b) = sig
            # assert vrify(s, b, hB, sPK2s[sender], rmt, ((round - 1) * 4) + 1, 1024)
            preset[pc_hB].put((sender, h, pi, voteset, sig))
            if preset[pc_hB].qsize() >=  (2 * f + 1) * T:
                c_hB = pc_hB
                o = 1
    if o == 1:
        print("get a valid omega set")
    else:
        print("not a valid omega set")

    commit(pid, sid, N, sPK2s, sSK2, rpk, rsk, rmt, round, o, preset[c_hB], c_hB, make_commit_send(round))

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
        if vrifymember(round, 4, h, pi, sPK2s[sender]):
            (s, b) = sig
            if vrify(s, b, str(omega) + str(c_hB_j), rpk_j, rmt_j, ((round - 1) * 4) + 3, 1024):
                omegaset[c_hB].put((sender, h, pi, omega, sig))
                if omegaset[c_hB].qsize() >= (2 * f + 1) * T:
                    g_hB = c_hB
                    pc = 1
    if pc == 1:
        print("get a valid PC set")
    else:
        print("not a valid PC set")

    if c_hB == g_hB:
        state = (g_hB, round, 2)
    elif (c_hB != g_hB and pc == 1) or (o == 0 and pc == 1):
        state = (g_hB, round, 1)
    elif o == 0 and pc == 0:
        state = (c_hB, round, 0)
    print(state)

    if round == 1:
        print(B)
    else:
        (h_s, round_s, g_s)= state
        if g_s == 2:
            if hash(lB) == B[0]:
                height += 1
                print("output in round ", round, B)
                lastcommit = 1
                lB = B
            else:
                while _tobe_commit.empty() is not True:
                    tB = _tobe_commit.get()
                    height += 1
                    print("output in round ", round, tB)
                height += 1
                print("output in round ", round, B)
                lastcommit = 1
                lB = B
        else:
            print("do not have commited block in round ", round)
            lastcommit = 0
            _tobe_commit.put(B)

