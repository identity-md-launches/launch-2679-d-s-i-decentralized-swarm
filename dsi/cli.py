"""scan --wallets wallets.json [--block N] [--candidates candidates.json]"""

import argparse
import json
import os
import re
import sys

from .config import load_config
from .report import write_json, write_md
from .scan import Scanner
from .transport import HttpTransport


def _addresses(path, key):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = data.get(key, [])
    out = []
    for item in data:
        entry = item if isinstance(item, dict) else {"address": item}
        a = entry.get("address")
        if not (isinstance(a, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", a)):
            raise SystemExit(f"{path}: bad address: {a!r}")
        out.append(entry)
    return out


def main(argv=None, transport=None, env=None):
    p = argparse.ArgumentParser(prog="scan", description="D.S.I: EIP-7702 / key-compromise exposure scanner for Ethereum wallets (read-only).")
    p.add_argument("--wallets", required=True, help="JSON list of addresses, or of {address, label}")
    p.add_argument("--block", type=int, help="report block (default: latest)")
    p.add_argument("--candidates", help="JSON list of extra contract addresses to confirm as owned")
    p.add_argument("--config", help="config file (default: $DSI_CONFIG or ./dsi.config.json)")
    p.add_argument("--out", default=".", help="directory for report.json and report.md")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    cfg = load_config(args.config, env)
    log = (lambda m: None) if args.quiet else (lambda m: print(m, file=sys.stderr))
    wallets = _addresses(args.wallets, "wallets")
    extra = [c["address"] for c in _addresses(args.candidates, "candidates")] if args.candidates else []

    scanner = Scanner(cfg, transport or HttpTransport(), log)
    reports = scanner.scan([w["address"] for w in wallets], args.block, extra)
    for r, w in zip(reports, wallets):
        if w.get("label"):
            r["label"] = w["label"]
    os.makedirs(args.out, exist_ok=True)
    write_json(os.path.join(args.out, "report.json"), reports)
    write_md(os.path.join(args.out, "report.md"), reports)
    log(f"wrote {os.path.join(args.out, 'report.json')} and report.md for {len(reports)} wallet(s) at block {reports[0]['block'] if reports else '-'}"
        f" ({scanner.history.getlogs_calls} eth_getLogs, {scanner.history.blockscout_calls} explorer calls)")
    return reports
