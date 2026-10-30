"""report.json and report.md."""

import json


def fmt_amount(raw, decimals):
    raw = int(raw)
    if decimals is None:
        return f"{raw} (raw)"
    whole, frac = divmod(raw, 10 ** decimals) if decimals else (raw, 0)
    s = f"{whole:,}"
    if decimals and frac:
        s += "." + str(frac).rjust(decimals, "0").rstrip("0")[:6]
    return s


def write_json(path, reports):
    with open(path, "w") as f:
        json.dump(reports, f, indent=2)
        f.write("\n")


def _delegation(d):
    if d["type"] == "eip7702-delegated":
        return f"**EIP-7702 delegated** to `{d['delegate']}`: whoever controls that code controls this wallet"
    if d["type"] == "contract":
        return f"contract ({d['codeBytes']} bytes of code)"
    return "plain account (no code, no delegation)"


def render_md(reports):
    out = ["# D.S.I exposure report", ""]
    for r in reports:
        label = f" ({r['label']})" if r.get("label") else ""
        out += [f"## {r['wallet']}{label}", "", f"Block {r['block']}", "",
                "| Section | Item | Detail | Amount |", "| --- | --- | --- | --- |",
                f"| Delegation | `{r['wallet']}` | {_delegation(r['delegation'])} | |"]
        if not r["ownedAccounts"]:
            out.append("| Owned account | none confirmed | | |")
        for o in r["ownedAccounts"]:
            via = ", ".join(o["confirmedBy"])
            out.append(f"| Owned account | `{o['address']}` | confirmed by {via} | {fmt_amount(o['ethWei'], 18)} ETH |")
            for t in o["tokens"]:
                out.append(f"| Owned account | `{o['address']}` | {t['symbol']} `{t['token']}` | {fmt_amount(t['raw'], t['decimals'])} {t['symbol']} |")
        if not r["allowances"]:
            out.append("| Allowance | none above zero | | |")
        for a in r["allowances"]:
            amount = "unlimited" if a["unlimited"] else f"{fmt_amount(a['allowance'], a['decimals'])} {a['symbol']}"
            out.append(f"| Allowance | {a['symbol']} `{a['token']}` | spender `{a['spender']}` | {amount} |")
        for s in r["valueAtStake"]:
            sym = s["symbol"]
            out.append(f"| Value at stake | {sym}" + (f" `{s['token']}`" if s["token"] != "ETH" else "")
                       + f" | wallet {fmt_amount(s['wallet'], s['decimals'])} + owned accounts "
                       f"{fmt_amount(s['ownedAccounts'], s['decimals'])} | {fmt_amount(s['total'], s['decimals'])} {sym} |")
        dropped = r["droppedCandidates"]
        if dropped:
            out += ["", f"{len(dropped)} candidate(s) not controlled by the wallet at this block: "
                    + ", ".join(f"`{d['address']}`" for d in dropped)]
        cov = []
        for name, c in r["historyCoverage"].items():
            if isinstance(c, dict) and "error" in c:
                cov.append(f"{name}: unavailable ({c['error']})")
            elif isinstance(c, dict):
                cov.append(f"{name}: blocks {c['fromBlock']}–{c['toBlock']} via {'+'.join(c['sources'])}")
            else:
                cov.append(f"{name}: {c}")
        out += ["", "History searched: " + "; ".join(cov) + ".", ""]
    return "\n".join(out)


def write_md(path, reports):
    with open(path, "w") as f:
        f.write(render_md(reports))
