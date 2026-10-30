"""The handful of ABI encodings the scanner needs: static arguments, Multicall3
aggregate3, and decoding of address / bool / uint256 / string results."""

from .keccak import selector

MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"


def word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def addr_word(address: str) -> bytes:
    return bytes(12) + bytes.fromhex(address[2:].rjust(40, "0"))


def call_data(signature: str, *args) -> bytes:
    """Encode a call with static arguments (address as 0x-str, int, or 32-byte bytes32 str)."""
    out = bytes.fromhex(selector(signature)[2:])
    for a in args:
        if isinstance(a, int):
            out += word(a)
        elif isinstance(a, str) and len(a) == 42:
            out += addr_word(a)
        elif isinstance(a, str) and len(a) == 66:
            out += bytes.fromhex(a[2:])
        else:
            raise ValueError(f"unsupported static argument {a!r}")
    return out


def encode_aggregate3(calls) -> str:
    """calls: list of (target, allow_failure, call_data bytes). Returns 0x-hex calldata."""
    head = bytes.fromhex(selector("aggregate3((address,bool,bytes)[])")[2:])
    body = word(32) + word(len(calls))
    tuples = []
    for target, allow_failure, data in calls:
        padded = data + bytes((-len(data)) % 32)
        tuples.append(addr_word(target) + word(1 if allow_failure else 0) + word(96) + word(len(data)) + padded)
    offset = 32 * len(calls)
    for t in tuples:
        body += word(offset)
        offset += len(t)
    return "0x" + (head + body + b"".join(tuples)).hex()


def _u(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 32], "big")


def decode_aggregate3(hexdata: str):
    """Returns list of (success, return_data bytes)."""
    data = bytes.fromhex(hexdata[2:])
    base = _u(data, 0)
    n = _u(data, base)
    arr = base + 32
    results = []
    for i in range(n):
        t = arr + _u(data, arr + 32 * i)
        success = _u(data, t) == 1
        b = t + _u(data, t + 32)
        length = _u(data, b)
        results.append((success, data[b + 32:b + 32 + length]))
    return results


def as_address(ret: bytes):
    """A 32-byte word holding a left-padded address, or None if it is not one."""
    if len(ret) < 32 or any(ret[:12]):
        return None
    return "0x" + ret[12:32].hex()


def as_bool(ret: bytes):
    if len(ret) < 32:
        return None
    v = _u(ret, 0)
    return {0: False, 1: True}.get(v)


def as_uint(ret: bytes):
    if len(ret) < 32:
        return None
    return _u(ret, 0)


def as_string(ret: bytes):
    """ABI string, or a bytes32 right-padded string (MKR-style symbol())."""
    if len(ret) == 32:
        return ret.rstrip(b"\x00").decode("utf-8", "replace") or None
    if len(ret) >= 64:
        off = _u(ret, 0)
        if off + 32 <= len(ret):
            length = _u(ret, off)
            raw = ret[off + 32:off + 32 + length]
            if len(raw) == length:
                return raw.decode("utf-8", "replace")
    return None


def as_addresses(ret: bytes):
    """An ABI-encoded address array, or None when the response is malformed."""
    if len(ret) < 64:
        return None
    off = _u(ret, 0)
    if off + 32 > len(ret):
        return None
    count = _u(ret, off)
    start = off + 32
    if start + 32 * count > len(ret):
        return None
    out = []
    for i in range(count):
        value = ret[start + 32 * i:start + 32 * (i + 1)]
        if any(value[:12]):
            return None
        out.append("0x" + value[12:].hex())
    return out
