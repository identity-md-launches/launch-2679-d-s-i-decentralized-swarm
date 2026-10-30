"""The 2026-10-29 incident as a sequence of scans, shared by the test and the recorder.

Binance 14 (0x28C6…1d60) carried an EIP-7702 delegation to 0x63e8…6fae from block
26300753 to 26301895; the Circle SingleOwnerMSCA 0xEe7a…4055 it natively owns was emptied
through it. The scans share one history cache, in this order.
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixtures", "incident-2026-10-29.json")
CONFIG = os.path.join(HERE, "fixtures", "incident-config.json")
WALLETS = os.path.join(HERE, "fixtures", "wallets.json")
CANDIDATES = os.path.join(HERE, "fixtures", "candidates.json")

WALLET = "0x28C6c06298d514Db089934071355E5743bf21d60"
DELEGATE = "0x63e842b054bd624a465454d533c33f573e9c6fae"
MSCA = "0xEe7aE85f2Fe2239E27D9c1E23fFFe168D63b4055"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

# (name, block, use candidates file)
STEPS = [
    ("before", 26300700, True),
    ("delegated", 26300760, False),
    ("cleared", 26301900, False),
    ("cleared-again", 26301900, False),
]


def run(step, transport, workdir, main):
    name, block, with_candidates = step
    out = os.path.join(workdir, name)
    argv = ["--wallets", WALLETS, "--block", str(block), "--config", CONFIG, "--out", out, "--quiet"]
    if with_candidates:
        argv += ["--candidates", CANDIDATES]
    env = {"DSI_CACHE_DIR": os.path.join(workdir, "cache")}
    if os.environ.get("DSI_RPC_URLS"):  # the recorder may route through another endpoint
        env["DSI_RPC_URLS"] = os.environ["DSI_RPC_URLS"]
    return main(argv, transport=transport, env=env), out
