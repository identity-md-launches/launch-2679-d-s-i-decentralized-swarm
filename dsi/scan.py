"""The exposure scan for one list of wallets at one block."""

import urllib.parse

from . import abi
from .history import HistoryUnavailable, LogHistory
from .keccak import topic
from .transport import RpcClient, TransportError

T_OWNERSHIP = topic("OwnershipTransferred(address,address)")  # OpenZeppelin Ownable
# Circle SingleOwnerMSCA and the ERC-6900 v0.7 SingleOwnerPlugin (circlefin/buidl-wallet-contracts)
# both emit OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner).
T_ACCOUNT_OWNERSHIP = topic("OwnershipTransferred(address,address,address)")
T_ROLE_GRANTED = topic("RoleGranted(bytes32,address,address)")
T_APPROVAL = topic("Approval(address,address,uint256)")

DELEGATION_PREFIX = "0xef0100"
UNLIMITED_THRESHOLD = 2 ** 255  # max uint256, and max after the token decremented it


def pad_topic(address):
    return "0x" + address.lower()[2:].rjust(64, "0")


def topic_address(t):
    return "0x" + t[-40:]


def checksum(address):
    from .keccak import keccak256
    a = address.lower()[2:]
    h = keccak256(a.encode()).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(a))


def classify_code(code):
    code = (code or "0x").lower()
    if code == "0x":
        return {"type": "plain-account", "delegate": None}
    if code.startswith(DELEGATION_PREFIX) and len(code) == 2 + 46:
        return {"type": "eip7702-delegated", "delegate": checksum("0x" + code[8:])}
    return {"type": "contract", "delegate": None, "codeBytes": (len(code) - 2) // 2}


class Scanner:
    def __init__(self, cfg, transport, log=None):
        self.cfg = cfg
        self.transport = transport
        self.log = log or (lambda msg: None)
        self.rpc = RpcClient(transport, cfg["rpcUrls"], cfg["chainId"], cfg["timeoutSeconds"], self.log, "rpc")
        archive = cfg.get("archiveRpcUrls") or cfg["rpcUrls"]
        self.archive = RpcClient(transport, archive, cfg["chainId"], cfg["timeoutSeconds"], self.log, "archive")
        self.history = LogHistory(cfg, self.rpc, transport, self.log)

    # ---- state reads -------------------------------------------------------
    def multicall(self, calls, block, state):
        """calls: list of (target, calldata bytes). Returns list of (success, bytes)."""
        out = []
        size = self.cfg["multicallBatchSize"]
        for i in range(0, len(calls), size):
            batch = [(t, True, d) for t, d in calls[i:i + size]]
            data = abi.encode_aggregate3(batch)
            ret = state.call("eth_call", [{"to": abi.MULTICALL3, "data": data}, hex(block)])
            out.extend(abi.decode_aggregate3(ret))
        return out

    # ---- candidates --------------------------------------------------------
    def _safe_candidates(self, wallet):
        base = self.cfg.get("safeTransactionService")
        if not base:
            return [], "disabled"
        url = f"{base.rstrip('/')}/api/v1/owners/{checksum(wallet)}/safes/"
        try:
            body = self.transport.get_json(url, self.cfg["timeoutSeconds"])
            return [s.lower() for s in body.get("safes", [])], "ok"
        except (TransportError, AttributeError) as e:
            self.log(f"safe service failed for {wallet}: {e}")
            return [], f"unavailable ({e})"

    def _collect(self, wallet, block, extra):
        w = pad_topic(wallet)
        filters = {
            "ownershipTransferred": [T_OWNERSHIP, None, w],
            "accountOwnershipTransferred": [T_ACCOUNT_OWNERSHIP, None, None, w],
            "roleGranted": [T_ROLE_GRANTED, None, w],
            "approval": [T_APPROVAL, w],
        }
        found, coverage = {}, {}
        for name, topics in filters.items():
            try:
                found[name], coverage[name] = self.history.logs(topics, block)
            except HistoryUnavailable as e:
                found[name], coverage[name] = [], {"error": str(e)}

        cands = {}

        def cand(addr, source):
            c = cands.setdefault(addr.lower(), {"sources": set(), "roles": set(), "plugins": set()})
            c["sources"].add(source)
            return c

        for l in found["ownershipTransferred"]:
            if len(l["topics"]) == 3:
                cand(l["address"], "event:OwnershipTransferred")
        for l in found["accountOwnershipTransferred"]:
            if len(l["topics"]) != 4:
                continue
            account = topic_address(l["topics"][1])
            if account == l["address"]:
                cand(account, "event:SingleOwnerMSCA.OwnershipTransferred")
            else:
                cand(account, "event:SingleOwnerPlugin.OwnershipTransferred")["plugins"].add(l["address"])
        for l in found["roleGranted"]:
            if len(l["topics"]) == 4:
                cand(l["address"], "event:RoleGranted")["roles"].add(l["topics"][1])
        safes, safe_status = self._safe_candidates(wallet)
        for s in safes:
            cand(s, "safe-transaction-service")
        for a in extra:
            cand(a, "candidates-file")
        coverage["safeTransactionService"] = safe_status

        pairs = sorted({(l["address"], topic_address(l["topics"][2])) for l in found["approval"] if len(l["topics"]) == 3})
        return cands, pairs, coverage

    # ---- confirmation ------------------------------------------------------
    def _confirm(self, wallet, cands, block, state):
        checks = []
        for addr, c in sorted(cands.items()):
            checks.append((addr, addr, "owner()", abi.call_data("owner()"), "address"))
            checks.append((addr, addr, "getNativeOwner()", abi.call_data("getNativeOwner()"), "address"))
            checks.append((addr, addr, "isOwner(wallet)", abi.call_data("isOwner(address)", wallet), "bool"))
            for role in sorted(c["roles"]):
                checks.append((addr, addr, f"hasRole({role},wallet)", abi.call_data("hasRole(bytes32,address)", role, wallet), "bool"))
            for plugin in sorted(c["plugins"]):
                checks.append((addr, plugin, f"{checksum(plugin)}.getOwnerOf(account)", abi.call_data("getOwnerOf(address)", addr), "address"))
        results = self.multicall([(target, data) for _, target, _, data, _ in checks], block, state)
        confirmed = {}
        for (addr, _, label, _, kind), (ok, ret) in zip(checks, results):
            if not ok:
                continue
            hit = abi.as_address(ret) == wallet if kind == "address" else abi.as_bool(ret) is True
            if hit:
                confirmed.setdefault(addr, []).append(label)
        owned, dropped = [], []
        for addr, c in sorted(cands.items()):
            entry = {"address": checksum(addr), "sources": sorted(c["sources"])}
            if addr in confirmed:
                entry["confirmedBy"] = confirmed[addr]
                if c["roles"]:
                    entry["roles"] = sorted(c["roles"])
                owned.append(entry)
            else:
                entry["reason"] = "no view call at the report block names the wallet as owner"
                dropped.append(entry)
        return owned, dropped

    # ---- tokens and balances -----------------------------------------------
    def _token_meta(self, tokens, block, state):
        calls = []
        for t in tokens:
            calls += [(t, abi.call_data("symbol()")), (t, abi.call_data("decimals()"))]
        res = self.multicall(calls, block, state)
        meta = {}
        for i, t in enumerate(tokens):
            (ok_s, sym), (ok_d, dec) = res[2 * i], res[2 * i + 1]
            d = abi.as_uint(dec) if ok_d else None
            meta[t] = {"symbol": (abi.as_string(sym) if ok_s else None) or "?",
                       "decimals": d if d is not None and d <= 77 else None}
        return meta

    def scan_wallet(self, wallet, block, state, extra_candidates):
        wallet = wallet.lower()
        code = state.call("eth_getCode", [checksum(wallet), hex(block)])
        delegation = classify_code(code)

        cands, pairs, coverage = self._collect(wallet, block, extra_candidates)
        owned, dropped = self._confirm(wallet, cands, block, state) if cands else ([], [])

        allowances = []
        if pairs:
            res = self.multicall([(t, abi.call_data("allowance(address,address)", wallet, s)) for t, s in pairs], block, state)
            for (t, s), (ok, ret) in zip(pairs, res):
                v = abi.as_uint(ret) if ok else None
                if v:
                    allowances.append({"token": t, "spender": s, "allowance": v, "unlimited": v >= UNLIMITED_THRESHOLD})

        approved_tokens = sorted({a["token"] for a in allowances})
        tokens = sorted({t.lower() for t in self.cfg["tokens"]} | set(approved_tokens))
        holders = [wallet] + [o["address"].lower() for o in owned]
        calls = [(abi.MULTICALL3, abi.call_data("getEthBalance(address)", h)) for h in holders]
        calls += [(t, abi.call_data("balanceOf(address)", h)) for h in holders for t in tokens]
        res = self.multicall(calls, block, state) if holders else []
        eth = {h: abi.as_uint(r) if ok else None for h, (ok, r) in zip(holders, res[:len(holders)])}
        bal = {}
        for (t, data), (ok, r) in zip(calls[len(holders):], res[len(holders):]):
            h = "0x" + data[-20:].hex()
            v = abi.as_uint(r) if ok else None
            if v:
                bal.setdefault(h, {})[t] = v
        meta = self._token_meta(tokens, block, state) if tokens else {}

        def token_entry(t, v):
            return {"token": checksum(t), "symbol": meta[t]["symbol"], "decimals": meta[t]["decimals"], "raw": str(v)}

        for o in owned:
            h = o["address"].lower()
            o["ethWei"] = str(eth.get(h) or 0)
            o["tokens"] = [token_entry(t, v) for t, v in sorted(bal.get(h, {}).items())]

        for a in allowances:
            a.update({"token": checksum(a["token"]), "spender": checksum(a["spender"]),
                      "symbol": meta[a["token"]]["symbol"], "decimals": meta[a["token"]]["decimals"],
                      "allowance": str(a["allowance"])})

        stake = []
        owned_eth = sum(int(o["ethWei"]) for o in owned)
        stake.append({"token": "ETH", "symbol": "ETH", "decimals": 18,
                      "wallet": str(eth.get(wallet) or 0), "ownedAccounts": str(owned_eth),
                      "total": str((eth.get(wallet) or 0) + owned_eth)})
        for t in tokens:
            w_bal = bal.get(wallet, {}).get(t, 0) if t in approved_tokens else 0
            o_bal = sum(bal.get(o["address"].lower(), {}).get(t, 0) for o in owned)
            if w_bal or o_bal:
                stake.append({**token_entry(t, w_bal + o_bal), "wallet": str(w_bal), "ownedAccounts": str(o_bal),
                              "total": str(w_bal + o_bal)})
                del stake[-1]["raw"]

        return {
            "wallet": checksum(wallet),
            "block": block,
            "delegation": delegation,
            "ownedAccounts": owned,
            "droppedCandidates": dropped,
            "allowances": allowances,
            "valueAtStake": stake,
            "historyCoverage": coverage,
        }

    def scan(self, wallets, block=None, candidates=()):
        if block is None:
            block = int(self.rpc.call("eth_blockNumber", []), 16)
            state = self.rpc
        else:
            state = self.archive
        extra = [c.lower() for c in candidates]
        return [self.scan_wallet(w, block, state, extra) for w in wallets]
