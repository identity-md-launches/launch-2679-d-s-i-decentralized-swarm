"""Offline unit tests: hashing, ABI, delegation parsing, and the confirmation rules
(allowance read at the block and > 0; a candidate the wallet lost is not owned)."""

import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dsi import abi  # noqa: E402
from dsi.config import load_config  # noqa: E402
from dsi.keccak import keccak256, selector, topic  # noqa: E402
from dsi.scan import Scanner, classify_code, pad_topic, T_APPROVAL, T_OWNERSHIP  # noqa: E402
from dsi.transport import HttpTransport  # noqa: E402

WALLET = "0x1111111111111111111111111111111111111111"
TOKEN_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
TOKEN_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
SPENDER = "0x5555555555555555555555555555555555555555"
STILL_OWNED = "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
GIVEN_AWAY = "0xd0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0"
OTHER = "0x9999999999999999999999999999999999999999"


def encode_results(results):
    """Inverse of abi.decode_aggregate3, for building fake Multicall3 answers."""
    w = abi.word
    tuples = []
    for ok, data in results:
        tuples.append(w(1 if ok else 0) + w(64) + w(len(data)) + data + bytes((-len(data)) % 32))
    body, off = w(len(results)), 32 * len(results)
    for t in tuples:
        body += w(off)
        off += len(t)
    return "0x" + (w(32) + body + b"".join(tuples)).hex()


def decode_calls(hexdata):
    data = bytes.fromhex(hexdata[10:])
    u = lambda p: int.from_bytes(data[p:p + 32], "big")  # noqa: E731
    n, arr = u(32), 64
    calls = []
    for i in range(n):
        t = arr + u(arr + 32 * i)
        target = "0x" + data[t + 12:t + 32].hex()
        b = t + u(t + 64)
        calls.append((target, data[b + 32:b + 32 + u(b)]))
    return calls


class FakeChain(HttpTransport):
    """A tiny chain: two Approval logs (one allowance since spent to zero), two
    OwnershipTransferred logs naming the wallet (one contract later given away)."""

    def __init__(self):
        super().__init__()
        self.blocks_called = set()

    def get_json(self, url, timeout):
        return {"safes": []}

    def post_rpc(self, url, body, timeout):
        m, p = body["method"], body["params"]
        res = None
        if m == "eth_chainId":
            res = "0x1"
        elif m == "eth_getCode":
            self.blocks_called.add(p[1])
            res = "0x"
        elif m == "eth_getLogs":
            t = p[0]["topics"]
            logs = []
            if t[0] == T_APPROVAL:
                logs = [{"address": a, "topics": [T_APPROVAL, pad_topic(WALLET), pad_topic(SPENDER)],
                         "data": "0x", "blockNumber": "0x10", "transactionHash": "0x" + a[2:4] * 32, "logIndex": "0x0"}
                        for a in (TOKEN_A, TOKEN_B)]
            elif t[0] == T_OWNERSHIP:
                logs = [{"address": a, "topics": [T_OWNERSHIP, pad_topic(OTHER), pad_topic(WALLET)],
                         "data": "0x", "blockNumber": "0x11", "transactionHash": "0x" + a[2:4] * 32, "logIndex": "0x1"}
                        for a in (STILL_OWNED, GIVEN_AWAY)]
            res = [l for l in logs if int(p[0]["fromBlock"], 16) <= 0x11 <= int(p[0]["toBlock"], 16)]
        elif m == "eth_call":
            self.blocks_called.add(p[1])
            res = encode_results([self.answer(t, d) for t, d in decode_calls(p[0]["data"])])
        return {"jsonrpc": "2.0", "id": body["id"], "result": res}

    def answer(self, target, data):
        sel = "0x" + data[:4].hex()
        if sel == selector("allowance(address,address)"):
            return True, abi.word(2 ** 256 - 1 if target == TOKEN_A else 0)
        if sel == selector("owner()"):
            return True, abi.addr_word(WALLET if target == STILL_OWNED else OTHER)
        if sel == selector("balanceOf(address)"):
            return True, abi.word(5 * 10 ** 6)
        if sel == selector("decimals()"):
            return True, abi.word(6)
        if sel == selector("symbol()"):
            return True, abi.word(32) + abi.word(3) + b"TKN" + bytes(29)
        if sel == selector("getEthBalance(address)"):
            return True, abi.word(10 ** 18)
        return False, b""


class Units(unittest.TestCase):
    def test_keccak(self):
        self.assertEqual(keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(selector("transfer(address,uint256)"), "0xa9059cbb")
        self.assertEqual(topic("Transfer(address,address,uint256)"),
                         "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
        self.assertEqual(selector("aggregate3((address,bool,bytes)[])"), "0x82ad56cb")

    def test_aggregate3_roundtrip(self):
        calls = [(TOKEN_A, abi.call_data("balanceOf(address)", WALLET)), (TOKEN_B, abi.call_data("decimals()"))]
        enc = abi.encode_aggregate3([(t, True, d) for t, d in calls])
        self.assertEqual(decode_calls(enc), calls)
        results = [(True, abi.word(7)), (False, b"\x08\xc3\x79\xa0")]
        self.assertEqual(abi.decode_aggregate3(encode_results(results)), results)

    def test_classify_code(self):
        self.assertEqual(classify_code("0x")["type"], "plain-account")
        d = classify_code("0xef010063e842b054bd624a465454d533c33f573e9c6fae")
        self.assertEqual(d["type"], "eip7702-delegated")
        self.assertEqual(d["delegate"], "0x63e842B054Bd624a465454D533C33F573e9c6fAe")
        self.assertEqual(classify_code("0x6080604052")["type"], "contract")

    def test_confirmation_rules(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = load_config(None, env={})
            cfg = {**cfg, "rpcUrls": ["https://example.invalid"], "tokens": [],
                   "history": {**cfg["history"], "sources": ["rpc"], "cacheDir": d}}
            chain = FakeChain()
            r = Scanner(cfg, chain).scan([WALLET], block=100)[0]
        self.assertEqual(chain.blocks_called, {"0x64"})  # every state read at the report block
        self.assertEqual([(a["token"].lower(), a["spender"].lower(), a["unlimited"]) for a in r["allowances"]],
                         [(TOKEN_A, SPENDER, True)])  # the zero allowance on TOKEN_B is not listed
        self.assertEqual([o["address"].lower() for o in r["ownedAccounts"]], [STILL_OWNED])
        self.assertEqual([o["address"].lower() for o in r["droppedCandidates"]], [GIVEN_AWAY])
        stake = {s["token"].lower(): s for s in r["valueAtStake"]}
        self.assertEqual(stake[TOKEN_A]["wallet"], str(5 * 10 ** 6))  # approved token: wallet balance counts
        self.assertNotIn(TOKEN_B, stake)  # not approved, not held by an owned account

    def test_read_only(self):
        forbidden = re.compile(r"eth_send|eth_sign|personal_|signTransaction|private_?key", re.I)
        for dirpath, _, files in os.walk(os.path.join(ROOT, "dsi")):
            for name in files:
                if name.endswith(".py"):
                    with open(os.path.join(dirpath, name)) as f:
                        self.assertIsNone(forbidden.search(f.read()), name)


if __name__ == "__main__":
    unittest.main()
