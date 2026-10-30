"""HTTP and JSON-RPC access with timeouts, endpoint rotation, and record/replay.

Every network request in the tool goes through an HttpTransport. Tests swap in a
ReplayTransport that answers from a recorded fixture and fails on anything else, so
the suite can never reach the network.
"""

import json
import time
import urllib.error
import urllib.request


class TransportError(Exception):
    """The request did not produce a usable HTTP response (timeout, refused, 5xx...)."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class RpcError(Exception):
    """The endpoint answered with a JSON-RPC error object."""

    def __init__(self, error):
        super().__init__(error.get("message", str(error)))
        self.code = error.get("code")


def _request_key(kind, url, body):
    # RPC requests are keyed on method+params only, so a fixture recorded through one
    # endpoint replays under any configured URL list; HTTP GETs are keyed on the URL.
    if kind == "rpc":
        return json.dumps(["rpc", body["method"], body["params"]], sort_keys=True)
    return json.dumps(["get", url])


class HttpTransport:
    def __init__(self, user_agent="dsi-scanner/1.0"):
        self.user_agent = user_agent
        self.sleep = time.sleep

    def _open(self, req, timeout):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raise TransportError(f"HTTP {e.code}", status=e.code) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            raise TransportError(f"{type(e).__name__}: {e}") from None

    def post_rpc(self, url, body, timeout):
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(), method="POST",
            headers={"content-type": "application/json", "user-agent": self.user_agent})
        return self._open(req, timeout)

    def get_json(self, url, timeout):
        req = urllib.request.Request(url, headers={"accept": "application/json", "user-agent": self.user_agent})
        return self._open(req, timeout)


class RecordingTransport(HttpTransport):
    """Passes requests through and writes each answer (or failure) into a fixture."""

    def __init__(self, path, inner=None):
        super().__init__()
        self.inner = inner or HttpTransport()
        self.path = path
        self.entries = {}

    def _record(self, key, fn):
        try:
            result = fn()
            self.entries.setdefault(key, []).append({"response": result})
            return result
        except TransportError as e:
            self.entries.setdefault(key, []).append({"transportError": str(e), "status": e.status})
            raise

    def post_rpc(self, url, body, timeout):
        return self._record(_request_key("rpc", url, body), lambda: self.inner.post_rpc(url, body, timeout))

    def get_json(self, url, timeout):
        return self._record(_request_key("get", url, None), lambda: self.inner.get_json(url, timeout))

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.entries, f, indent=1, sort_keys=True)
            f.write("\n")


class ReplayTransport(HttpTransport):
    """Answers from a fixture. Repeated requests get the recorded answers in order, then
    the last one again. An unrecorded request is an error, never a network call."""

    def __init__(self, path):
        super().__init__()
        with open(path) as f:
            self.entries = json.load(f)
        self.cursor = {}
        self.calls = []
        self.sleep = lambda seconds: None

    def _replay(self, key):
        self.calls.append(json.loads(key))
        if key not in self.entries:
            raise AssertionError(f"request not in fixture: {key[:200]}")
        answers = self.entries[key]
        i = self.cursor.get(key, 0)
        self.cursor[key] = i + 1
        entry = answers[min(i, len(answers) - 1)]
        if "transportError" in entry:
            raise TransportError(entry["transportError"], status=entry.get("status"))
        return entry["response"]

    def post_rpc(self, url, body, timeout):
        return self._replay(_request_key("rpc", url, body))

    def get_json(self, url, timeout):
        return self._replay(_request_key("get", url, None))


class RpcClient:
    """JSON-RPC over a rotation list of endpoints.

    Each endpoint is checked with eth_chainId before first use. 429/503 are retried twice
    on the same endpoint with a growing pause; any other transport failure (or a third
    refusal) retires the endpoint for the rest of the run and moves to the next one.
    """

    def __init__(self, transport, urls, chain_id, timeout, log=None, label="rpc"):
        if not urls:
            raise ValueError(f"no {label} endpoints configured")
        self.transport = transport
        self.urls = list(urls)
        self.chain_id = chain_id
        self.timeout = timeout
        self.log = log or (lambda msg: None)
        self.label = label
        self.index = 0
        self.checked = set()
        self.next_id = 1

    def _post(self, url, method, params):
        body = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        self.next_id += 1
        for attempt in range(3):
            try:
                reply = self.transport.post_rpc(url, body, self.timeout)
                break
            except TransportError as e:
                if e.status in (429, 503) and attempt < 2:
                    self.transport.sleep(1.5 * (attempt + 1))
                    continue
                raise
        if not isinstance(reply, dict):
            raise TransportError("malformed JSON-RPC body")
        if reply.get("error"):
            raise RpcError(reply["error"])
        if "result" not in reply:
            raise TransportError("JSON-RPC body without result")
        return reply["result"]

    def retire_current(self, reason):
        if self.index < len(self.urls):
            self.log(f"{self.label}: retiring {self.urls[self.index]} ({reason})")
            self.index += 1

    def call(self, method, params, rotate=True):
        """rotate=False hands a transport failure back to the caller instead of retiring the
        endpoint (eth_getLogs uses this: a timeout there usually means 'range too large')."""
        while self.index < len(self.urls):
            url = self.urls[self.index]
            try:
                if url not in self.checked:
                    got = int(self._post(url, "eth_chainId", []), 16)
                    if got != self.chain_id:
                        raise TransportError(f"endpoint is chain {got}, expected {self.chain_id}")
                    self.checked.add(url)
                    self.log(f"{self.label}: using {url}")
                return self._post(url, method, params)
            except (TransportError, RpcError) as e:
                if not rotate and url in self.checked:
                    raise
                self.log(f"{self.label}: {url} failed ({e}); rotating")
                self.index += 1
        raise TransportError(f"every {self.label} endpoint failed")
