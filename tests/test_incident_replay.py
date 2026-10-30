"""Replays the recorded 2026-10-29 incident offline. Any request not in the fixture fails."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dsi.cli import main  # noqa: E402
from dsi.transport import ReplayTransport  # noqa: E402
import scenario  # noqa: E402


def getlogs_calls(transport):
    return [c for c in transport.calls if c[0] == "rpc" and c[1] == "eth_getLogs"]


def explorer_log_calls(transport):
    return [c for c in transport.calls if c[0] == "get" and "module=logs" in c[1]]


class IncidentReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        cls.results = {}
        for step in scenario.STEPS:
            transport = ReplayTransport(scenario.FIXTURE)
            reports, out = scenario.run(step, transport, cls.work.name, main)
            cls.results[step[0]] = (reports[0], transport, out)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def test_delegated_during_incident(self):
        r = self.results["delegated"][0]
        self.assertEqual(r["block"], 26300760)
        self.assertEqual(r["wallet"], scenario.WALLET)
        self.assertEqual(r["delegation"]["type"], "eip7702-delegated")
        self.assertEqual(r["delegation"]["delegate"].lower(), scenario.DELEGATE)

    def test_plain_account_after_clearing(self):
        r = self.results["cleared"][0]
        self.assertEqual(r["block"], 26301900)
        self.assertEqual(r["delegation"], {"type": "plain-account", "delegate": None})

    def test_msca_owned_before_incident_with_usdc(self):
        r = self.results["before"][0]
        self.assertEqual(r["block"], 26300700)
        self.assertEqual(r["delegation"]["type"], "plain-account")
        owned = {o["address"]: o for o in r["ownedAccounts"]}
        self.assertIn(scenario.MSCA, owned)
        msca = owned[scenario.MSCA]
        self.assertIn("getNativeOwner()", msca["confirmedBy"])
        self.assertIn("event:SingleOwnerMSCA.OwnershipTransferred", msca["sources"])
        usdc = [t for t in msca["tokens"] if t["token"] == scenario.USDC]
        self.assertEqual(len(usdc), 1)
        self.assertEqual(usdc[0]["symbol"], "USDC")
        self.assertEqual(usdc[0]["decimals"], 6)
        self.assertGreater(int(usdc[0]["raw"]), 0)
        stake = {s["symbol"]: s for s in r["valueAtStake"]}
        self.assertEqual(stake["USDC"]["ownedAccounts"], usdc[0]["raw"])

    def test_candidate_not_controlled_is_not_owned(self):
        r = self.results["before"][0]
        owned = {o["address"] for o in r["ownedAccounts"]}
        dropped = {d["address"] for d in r["droppedCandidates"]}
        self.assertNotIn(scenario.USDC, owned)
        self.assertIn(scenario.USDC, dropped)

    def test_listed_allowances_are_positive(self):
        for reports, _, _ in self.results.values():
            for a in reports["allowances"]:
                self.assertGreater(int(a["allowance"]), 0)

    def test_history_appends_only_new_blocks(self):
        prev_watermark = 26300760
        for c in getlogs_calls(self.results["cleared"][1]):
            self.assertGreater(int(c[2][0]["fromBlock"], 16), prev_watermark)
        for c in explorer_log_calls(self.results["cleared"][1]):
            self.assertIn(f"fromBlock={prev_watermark + 1}&", c[1])

    def test_second_run_same_range_makes_no_log_calls(self):
        transport = self.results["cleared-again"][1]
        self.assertEqual(getlogs_calls(transport), [])
        self.assertEqual(explorer_log_calls(transport), [])
        self.assertEqual(self.results["cleared-again"][0], self.results["cleared"][0])

    def test_reports_written(self):
        _, _, out = self.results["delegated"]
        with open(os.path.join(out, "report.json")) as f:
            data = json.load(f)
        self.assertEqual(len(data), 1)
        with open(os.path.join(out, "report.md")) as f:
            md = f.read()
        self.assertIn("EIP-7702 delegated", md)
        self.assertIn(scenario.MSCA, md)


if __name__ == "__main__":
    unittest.main()
