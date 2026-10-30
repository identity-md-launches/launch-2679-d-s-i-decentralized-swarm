"""Event history with an on-disk watermark.

Each log filter (a topic list) has one store file holding the logs found so far and the
block range they cover. A scan at block N reads the store; only blocks above the stored
watermark are fetched, and they are appended. Nothing is ever rescanned.

Sources, tried in the configured order for every missing range:
  blockscout  the explorer's keyless logs API (`/api?module=logs&action=getLogs`)
  rpc         chunked eth_getLogs, halving the chunk on any refusal or timeout
"""

import hashlib
import json
import os
import re
import urllib.parse

from .transport import RpcError, TransportError

# How public nodes word "this eth_getLogs request is too large" in a JSON-RPC error.
RANGE_LIMIT = re.compile(r"range|limit|too many|too large|exceed|max(imum)? .*(blocks|results)|response size", re.I)


class HistoryUnavailable(Exception):
    pass


def _int(v):
    if isinstance(v, int):
        return v
    if v in (None, ""):
        return 0
    return int(v, 16) if str(v).startswith("0x") else int(v)


def _normalize(log):
    return {
        "address": log["address"].lower(),
        "topics": [t.lower() for t in log["topics"] if t],
        "data": log.get("data") or "0x",
        "blockNumber": _int(log["blockNumber"]),
        "transactionHash": (log.get("transactionHash") or "").lower(),
        "logIndex": _int(log.get("logIndex")),
    }


class LogHistory:
    def __init__(self, cfg, rpc, transport, log=None):
        h = cfg["history"]
        self.h = h
        self.chain_id = cfg["chainId"]
        self.rpc = rpc
        self.transport = transport
        self.log = log or (lambda msg: None)
        self.dir = os.path.join(h["cacheDir"], str(self.chain_id))
        self.getlogs_calls = 0
        self.blockscout_calls = 0

    # ---- store -------------------------------------------------------------
    def _path(self, topics):
        key = hashlib.sha256(json.dumps(topics).encode()).hexdigest()[:24]
        return os.path.join(self.dir, f"logs-{key}.json")

    def _load(self, topics):
        p = self._path(topics)
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return json.load(f)

    def _save(self, store):
        os.makedirs(self.dir, exist_ok=True)
        p = self._path(store["topics"])
        tmp = p + ".tmp"
        with open(tmp, "w") as f:
            json.dump(store, f)
        os.replace(tmp, p)

    @staticmethod
    def _append(store, logs, to_block, source):
        seen = {(l["transactionHash"], l["logIndex"]) for l in store["logs"]}
        for l in map(_normalize, logs):
            if (l["transactionHash"], l["logIndex"]) not in seen:
                store["logs"].append(l)
                seen.add((l["transactionHash"], l["logIndex"]))
        store["toBlock"] = to_block
        if source not in store["sources"]:
            store["sources"].append(source)

    # ---- public ------------------------------------------------------------
    def logs(self, topics, to_block):
        """Logs matching `topics` up to `to_block`, plus the range the store covers."""
        store = self._load(topics)
        if store is None or store["toBlock"] < to_block:
            store = self._extend(topics, store, to_block)
        logs = [l for l in store["logs"] if store["fromBlock"] <= l["blockNumber"] <= to_block]
        coverage = {"fromBlock": store["fromBlock"], "toBlock": store["toBlock"], "sources": store["sources"]}
        return logs, coverage

    def _extend(self, topics, store, to_block):
        errors = []
        for source in self.h["sources"]:
            try:
                if source == "blockscout":
                    start = store["toBlock"] + 1 if store else self.h["blockscoutStartBlock"]
                    found, covered_to = self._blockscout(topics, start, to_block)
                    if store is None:
                        store = {"topics": topics, "fromBlock": start, "toBlock": start - 1, "sources": [], "logs": []}
                    self._append(store, found, covered_to, "blockscout")
                    self._save(store)
                    return store
                if source == "rpc":
                    if store is None:
                        start = self.h["rpcStartBlock"]
                        store = {"topics": topics, "fromBlock": start, "toBlock": start - 1, "sources": [], "logs": []}
                    self._rpc_backfill(store, to_block)
                    return store
                raise HistoryUnavailable(f"unknown history source {source!r}")
            except (HistoryUnavailable, TransportError) as e:
                self.log(f"history: {source} failed for {topics[0][:10]}… ({e})")
                errors.append(f"{source}: {e}")
        raise HistoryUnavailable("; ".join(errors))

    def _blockscout(self, topics, start, end):
        # This action is served from Blockscout's indexed database.  It is not
        # interchangeable with an RPC node's head: advancing past it would make
        # a later scan believe unindexed blocks had been searched.
        head_url = self.h["blockscoutUrl"].rstrip("/") + "/api?module=block&action=eth_block_number"
        self.blockscout_calls += 1
        head = self.transport.get_json(head_url, self.h["blockscoutTimeoutSeconds"])
        if not isinstance(head, dict) or head.get("result") in (None, ""):
            raise HistoryUnavailable("blockscout returned no indexed head")
        try:
            indexed_head = _int(head["result"])
        except (TypeError, ValueError):
            raise HistoryUnavailable("blockscout returned an invalid indexed head") from None
        end = min(end, indexed_head)
        if end < start:
            raise HistoryUnavailable(f"blockscout indexed through {indexed_head}, before block {start}")
        out = []
        frm = start
        while True:
            q = {"module": "logs", "action": "getLogs", "fromBlock": frm, "toBlock": end}
            for i, t in enumerate(topics):
                if t is not None:
                    q[f"topic{i}"] = t
                    if i:
                        q[f"topic0_{i}_opr"] = "and"
            url = self.h["blockscoutUrl"].rstrip("/") + "/api?" + urllib.parse.urlencode(q)
            self.blockscout_calls += 1
            body = self.transport.get_json(url, self.h["blockscoutTimeoutSeconds"])
            if not isinstance(body, dict):
                raise HistoryUnavailable("blockscout returned no object")
            result = body.get("result")
            if body.get("status") != "1":
                if body.get("message") == "No logs found" and result == []:
                    return out, end
                raise HistoryUnavailable(f"blockscout said {body.get('message')!r}")
            if not isinstance(result, list):
                raise HistoryUnavailable("blockscout returned no list")
            out.extend(result)
            if len(result) < 1000:
                return out, end
            last = _int(result[-1]["blockNumber"])
            if last <= frm:
                raise HistoryUnavailable("more than one page of logs in a single block")
            frm = last  # the store de-duplicates the overlap

    def _rpc_backfill(self, store, to_block):
        chunk = self.h["rpcChunkBlocks"]
        frm = store["toBlock"] + 1
        while frm <= to_block:
            end = min(frm + chunk - 1, to_block)
            flt = {"fromBlock": hex(frm), "toBlock": hex(end), "topics": store["topics"]}
            try:
                self.getlogs_calls += 1
                found = self.rpc.call("eth_getLogs", [flt], rotate=False)
            except RpcError as e:
                if chunk > 1 and RANGE_LIMIT.search(str(e)):
                    # A range or result-size limit is a property of the request: shrink it.
                    chunk = max(1, chunk // 2)
                    self.log(f"history: eth_getLogs {frm}-{end} refused ({e}); chunk now {chunk}")
                    continue
                # Any other JSON-RPC error is an endpoint failure, not an empty range.
                # Rotate before retrying this exact chunk on the next endpoint.
                self.rpc.retire_current(str(e))
                if self.rpc.index >= len(self.rpc.urls):
                    raise TransportError(f"no endpoint left for eth_getLogs ({e})")
                continue
            except TransportError as e:
                if self.rpc.index >= len(self.rpc.urls):
                    raise TransportError(f"no endpoint left for eth_getLogs ({e})")
                if chunk > 1:
                    chunk = max(1, chunk // 2)
                    self.log(f"history: eth_getLogs {frm}-{end} refused ({e}); chunk now {chunk}")
                    continue
                self.rpc.retire_current(str(e))
                chunk = self.h["rpcChunkBlocks"]
                continue
            if not isinstance(found, list):
                raise TransportError("eth_getLogs returned no list")
            self._append(store, found, end, "rpc")
            self._save(store)  # watermark advances chunk by chunk, so an interrupted run resumes
            frm = end + 1
            chunk = min(chunk * 2, self.h["rpcMaxChunkBlocks"])
