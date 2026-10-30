"""Re-record tests/fixtures/incident-2026-10-29.json from the network.

    DSI_RPC_URLS=<archive-capable mainnet RPC> python3 tests/record_fixture.py

Needs an endpoint that serves eth_call / eth_getCode at old blocks. Only request
method+params and responses are stored, never the endpoint URL.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dsi.cli import main  # noqa: E402
from dsi.transport import RecordingTransport  # noqa: E402
from scenario import FIXTURE, STEPS, run  # noqa: E402

if __name__ == "__main__":
    rec = RecordingTransport(FIXTURE)
    with tempfile.TemporaryDirectory() as work:
        for step in STEPS:
            reports, _ = run(step, rec, work, main)
            r = reports[0]
            print(step[0], r["block"], r["delegation"], [o["address"] for o in r["ownedAccounts"]])
    rec.save()
    print("wrote", FIXTURE, len(rec.entries), "distinct requests")
