"""Offline unit tests: hashing, ABI, delegation parsing, and the confirmation rules
(allowance read at the block and > 0; a candidate the wallet lost is not owned)."""

import os
import json
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
from dsi.history import LogHistory  # noqa: E402
from dsi.transport import HttpTransport, RpcClient, TransportError  # noqa: E402

WALLET = "0x1111111111111111111111111111111111111111"
TOKEN_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
TOKEN_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
SPENDER = "0x5555555555555555555555555555555555555555"
STILL_OWNED = "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
GIVEN_AWAY = "0xd0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0"
OTHER = "0x9999999999999999999999999999999999999999"
SAFE_ONE = "0x1212121212121212121212121212121212121212"
SAFE_SHARED = "0x1313131313131313131313131313131313131313"
SECOND_WALLET = "0x2222222222222222222222222222222222222222"


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


def addresses_result(addresses):
    return abi.word(32) + abi.word(len(addresses)) + b"".join(abi.addr_word(a) for a in addresses)


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


class SafeChain(FakeChain):
    def get_json(self, url, timeout):
        return {"safes": [SAFE_ONE, SAFE_SHARED]}

    def answer(self, target, data):
        sel = "0x" + data[:4].hex()
        if target in (SAFE_ONE, SAFE_SHARED):
            if sel == selector("isOwner(address)"):
                return True, abi.word(1)
            if sel == selector("getThreshold()"):
                return True, abi.word(1 if target == SAFE_ONE else 2)
            if sel == selector("getOwners()"):
                return True, addresses_result([WALLET, OTHER])
            if sel == selector("getEthBalance(address)"):
                return True, abi.word(3 * 10 ** 18)
        return super().answer(target, data)


class ShortMulticallChain(FakeChain):
    def post_rpc(self, url, body, timeout):
        reply = super().post_rpc(url, body, timeout)
        if body["method"] == "eth_call":
            calls = decode_calls(body["params"][0]["data"])
            reply["result"] = encode_results([self.answer(*calls[0])])
        return reply


class RotatingChain(HttpTransport):
    def __init__(self, fail_wallet=None):
        super().__init__()
        self.urls = []
        self.fail_wallet = fail_wallet

    def get_json(self, url, timeout):
        return {"safes": []}

    def post_rpc(self, url, body, timeout):
        self.urls.append(url)
        method, params = body["method"], body["params"]
        if method == "eth_chainId":
            result = "0x1"
        elif method == "eth_getCode" and (url.endswith("one") or params[0].lower() == self.fail_wallet):
            return {"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32000, "message": "unavailable"}}
        elif method == "eth_getCode":
            result = "0x"
        elif method == "eth_getLogs":
            result = []
        elif method == "eth_call":
            result = encode_results([FakeChain().answer(t, d) for t, d in decode_calls(params[0]["data"])])
        else:
            result = "0x0"
        return {"jsonrpc": "2.0", "id": body["id"], "result": result}


class LaggingExplorer(HttpTransport):
    def __init__(self):
        super().__init__()
        self.head = 10
        self.ranges = []

    def get_json(self, url, timeout):
        if "action=eth_block_number" in url:
            return {"status": "1", "result": str(self.head)}
        self.ranges.append(url)
        return {"status": "1", "result": []}


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

    def test_short_multicall_answer_is_an_error(self):
        cfg = load_config(None, env={})
        cfg = {**cfg, "rpcUrls": ["https://example.invalid"], "tokens": [],
               "history": {**cfg["history"], "sources": ["rpc"]}}
        with self.assertRaisesRegex(TransportError, "1 results for 2 calls"):
            Scanner(cfg, ShortMulticallChain()).multicall(
                [(TOKEN_A, abi.call_data("balanceOf(address)", WALLET)),
                 (TOKEN_B, abi.call_data("balanceOf(address)", WALLET))], 100,
                Scanner(cfg, ShortMulticallChain()).rpc)

    def test_safe_threshold_controls_value_at_stake(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = load_config(None, env={})
            cfg = {**cfg, "rpcUrls": ["https://example.invalid"], "tokens": [],
                   "history": {**cfg["history"], "sources": ["rpc"], "cacheDir": d}}
            report = Scanner(cfg, SafeChain()).scan([WALLET], block=100)[0]
        owned = {entry["address"].lower(): entry for entry in report["ownedAccounts"]}
        self.assertEqual(owned[SAFE_ONE]["threshold"], 1)
        self.assertEqual(owned[SAFE_ONE]["owners"][0].lower(), WALLET)
        self.assertEqual([entry["address"].lower() for entry in report["sharedControl"]], [SAFE_SHARED])
        self.assertEqual(report["sharedControl"][0]["threshold"], 2)
        self.assertEqual(report["valueAtStake"][0]["ownedAccounts"], str(2 * 10 ** 18))

    def test_rpc_error_rotates_to_next_endpoint(self):
        chain = RotatingChain()
        client = RpcClient(chain, ["https://rpc.one", "https://rpc.two"], 1, 1)
        self.assertEqual(client.call("eth_getCode", [WALLET, "latest"]), "0x")
        self.assertIn("https://rpc.one", chain.urls)
        self.assertIn("https://rpc.two", chain.urls)

    def test_lagging_explorer_watermark_and_later_append(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = load_config(None, env={})
            cfg = {**cfg, "history": {**cfg["history"], "sources": ["blockscout"], "cacheDir": d}}
            explorer = LaggingExplorer()
            history = LogHistory(cfg, None, explorer)
            _, coverage = history.logs([T_APPROVAL, pad_topic(WALLET)], 20)
            self.assertEqual(coverage["toBlock"], 10)
            explorer.head = 20
            _, coverage = history.logs([T_APPROVAL, pad_topic(WALLET)], 20)
            self.assertEqual(coverage["toBlock"], 20)
            self.assertTrue(any("fromBlock=11" in url for url in explorer.ranges))

    def test_failed_wallet_still_writes_other_wallet_report(self):
        with tempfile.TemporaryDirectory() as d:
            wallets = os.path.join(d, "wallets.json")
            config = os.path.join(d, "config.json")
            with open(wallets, "w") as f:
                json.dump([WALLET, SECOND_WALLET], f)
            with open(config, "w") as f:
                json.dump({"rpcUrls": ["https://rpc.one", "https://rpc.two"],
                           "archiveRpcUrls": ["https://rpc.one", "https://rpc.two"],
                           "tokens": [], "history": {"sources": ["rpc"], "cacheDir": os.path.join(d, "cache")}}, f)
            from dsi.cli import main
            reports = main(["--wallets", wallets, "--block", "100", "--config", config, "--out", d, "--quiet"],
                           transport=RotatingChain(fail_wallet=WALLET), env={})
            self.assertIn("error", reports[0])
            self.assertNotIn("error", reports[1])
            with open(os.path.join(d, "report.json")) as f:
                self.assertEqual(len(json.load(f)), 2)
            with open(os.path.join(d, "report.md")) as f:
                self.assertIn(SECOND_WALLET, f.read().lower())

    def test_read_only(self):
        forbidden = re.compile(r"eth_send|eth_sign|personal_|signTransaction|private_?key", re.I)
        for dirpath, _, files in os.walk(os.path.join(ROOT, "dsi")):
            for name in files:
                if name.endswith(".py"):
                    with open(os.path.join(dirpath, name)) as f:
                        self.assertIsNone(forbidden.search(f.read()), name)


if __name__ == "__main__":
    unittest.main()
