"""Configuration: a JSON file (default dsi.config.json, if present) overlaid by env vars."""

import json
import os

DEFAULTS = {
    "chainId": 1,
    # Public Ethereum mainnet endpoints, fastest first, one per operator. Used in order;
    # a failing endpoint is retired for the run.
    "rpcUrls": [
        "https://rpc.flashbots.net/fast",
        "https://rpc.mevblocker.io/fast",
        "https://one.valve.city/rpc/vk_demo/evm/1",
        "https://ethereum-rpc.publicnode.com",
        "https://virginia.rpc.blxrbdn.com",
    ],
    # Endpoints that serve state at old blocks. Used whenever --block is given.
    # Empty means "use rpcUrls" (many public nodes refuse historical eth_call).
    "archiveRpcUrls": [],
    "timeoutSeconds": 30,
    "history": {
        # Where log history comes from, tried in order for each filter.
        "sources": ["blockscout", "rpc"],
        "blockscoutUrl": "https://eth.blockscout.com",
        "blockscoutTimeoutSeconds": 30,
        # First block the explorer source covers; the explorer indexes all of history.
        "blockscoutStartBlock": 0,
        # First block of the eth_getLogs backfill when the explorer does not answer.
        "rpcStartBlock": 0,
        "rpcChunkBlocks": 50000,
        "rpcMaxChunkBlocks": 500000,
        "cacheDir": ".dsi-cache",
    },
    "safeTransactionService": "https://safe-transaction-mainnet.safe.global",
    "multicallBatchSize": 150,
    # Tokens whose balances are always read for owned accounts (approved tokens are added).
    "tokens": [
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
    ],
}


def _merge(base, override):
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _urls(value):
    return [u.strip() for u in value.split(",") if u.strip()]


def load_config(path=None, env=None):
    env = os.environ if env is None else env
    cfg = DEFAULTS
    path = path or env.get("DSI_CONFIG")
    if path is None and os.path.exists("dsi.config.json"):
        path = "dsi.config.json"
    if path:
        with open(path) as f:
            cfg = _merge(cfg, json.load(f))
    if env.get("DSI_RPC_URLS"):
        cfg = _merge(cfg, {"rpcUrls": _urls(env["DSI_RPC_URLS"])})
    if env.get("DSI_ARCHIVE_RPC_URLS"):
        cfg = _merge(cfg, {"archiveRpcUrls": _urls(env["DSI_ARCHIVE_RPC_URLS"])})
    if env.get("DSI_CACHE_DIR"):
        cfg = _merge(cfg, {"history": {"cacheDir": env["DSI_CACHE_DIR"]}})
    if env.get("DSI_TIMEOUT"):
        cfg = _merge(cfg, {"timeoutSeconds": float(env["DSI_TIMEOUT"])})
    return cfg
