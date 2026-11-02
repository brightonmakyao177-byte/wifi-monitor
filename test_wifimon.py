import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import wifimon

INTERVAL = 60
GRACE = 300
A = "aa:00:00:00:00:01"
B = "00:11:22:00:00:02"


class DbTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = wifimon.connect(Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def scan(self, ts, *macs):
        return wifimon.record_scan(self.db, ts, {m: "10.0.0.5" for m in macs}, INTERVAL, GRACE)

    def sessions(self, mac):
        rows = self.db.execute("SELECT start, end, open FROM sessions WHERE mac = ? ORDER BY start", (mac,))
        return [tuple(r) for r in rows]

    def online(self, ts):
        return self.db.execute("SELECT online FROM scans WHERE ts = ?", (ts,)).fetchone()["online"]


class RecordScanTest(DbTestCase):
    def test_reports_only_first_sightings_as_new(self):
        self.assertEqual(self.scan(1000, A), [A])
        self.assertEqual(self.scan(1060, A, B), [B])
        self.assertEqual(self.scan(1120, A, B), [])

    def test_short_silence_keeps_one_session_and_the_count(self):
        self.scan(1000, A, B)
        self.scan(1060, B)  # A missed one scan, as a sleeping phone does.
        self.assertEqual(self.online(1060), 2)
        self.scan(1120, A, B)
        self.assertEqual(self.sessions(A), [(1000, 1120, 1)])

    def test_long_silence_ends_session_at_last_answer(self):
        self.scan(1000, A, B)
        for ts in range(1060, 1361, 60):
            self.scan(ts, B)
        self.assertEqual(self.online(1360), 1)
        self.assertEqual(self.sessions(A), [(1000, 1000, 0)])

    def test_return_after_leaving_starts_new_session(self):
        self.scan(1000, A, B)
        for ts in range(1060, 1361, 60):
            self.scan(ts, B)
        self.scan(1420, A, B)
        self.assertEqual(self.sessions(A), [(1000, 1000, 0), (1420, 1420, 1)])

    def test_monitor_downtime_does_not_extend_sessions(self):
        self.scan(1000, A)
        self.scan(9000, A)
        self.assertEqual(self.sessions(A), [(1000, 1000, 0), (9000, 9000, 1)])


class StateTest(DbTestCase):
    def state(self, now, hours=1):
        return wifimon.build_state(self.db, hours, INTERVAL, GRACE, {"state": "ok"}, now=now)

    def test_downtime_appears_as_a_gap(self):
        self.scan(10000, A)
        self.scan(10060, A)
        self.scan(11000, A)
        state = self.state(11010)
        self.assertEqual(state["gaps"], [[11010 - 3600, 10000], [10060, 11000]])
        self.assertEqual(state["online"], 1)

    def test_stopped_monitor_reports_unknown_not_stale_count(self):
        self.scan(10000, A)
        state = self.state(10000 + GRACE + 1)
        self.assertIsNone(state["online"])
        self.assertEqual(state["gaps"][-1], [10000, 10000 + GRACE + 1])

    def test_peak_and_counts(self):
        self.scan(10000, A)
        self.scan(10060, A, B)
        state = self.state(10100)
        self.assertEqual(state["peak"]["online"], 2)
        self.assertEqual(state["active"], 2)
        self.assertEqual(state["new"], 2)

    def test_no_scans_is_all_gap(self):
        self.assertEqual(self.state(5000)["gaps"], [[5000 - 3600, 5000]])


class HelpersTest(unittest.TestCase):
    def test_neighbours_go_by_answer_age_not_state(self):
        entries = [
            {"dst": "10.0.0.1", "lladdr": "AA:00:00:00:00:01", "confirmed": 30, "state": ["STALE"]},
            {"dst": "10.0.0.2", "lladdr": "aa:00:00:00:00:02", "confirmed": 300, "state": ["STALE"]},
            {"dst": "10.0.0.3", "lladdr": "aa:00:00:00:00:03", "confirmed": 1, "state": ["REACHABLE"]},
            {"dst": "10.0.0.4", "confirmed": 1, "state": ["FAILED"]},
        ]
        with mock.patch.object(wifimon, "run", return_value=json.dumps(entries)):
            seen = wifimon.read_neighbours("wlan0", 15)
        self.assertEqual(seen, {"aa:00:00:00:00:01": "10.0.0.1", "aa:00:00:00:00:03": "10.0.0.3"})

    def test_private_mac(self):
        self.assertTrue(wifimon.is_private_mac("da:a1:19:00:00:01"))
        self.assertFalse(wifimon.is_private_mac("00:11:22:00:00:01"))

    def test_sweep_targets_exclude_self_and_cap_at_slash_24(self):
        targets = wifimon.sweep_targets("192.168.100.22", 16)
        self.assertEqual(len(targets), 253)
        self.assertNotIn("192.168.100.22", targets)


class WindowsParsingTest(unittest.TestCase):
    SCRIPT = json.dumps({"gateway": "192.168.1.1", "ip": "192.168.1.9", "prefix": 24, "mac": "AA-BB-CC-00-11-22", "dev": "Wi-Fi"})
    NETSH = "    Name : Wi-Fi\n    SSID                   : Home Net 5G\n    BSSID                  : aa:bb\n"

    def test_network_details(self):
        net = wifimon.parse_windows_network(self.SCRIPT, self.NETSH)
        self.assertEqual(net["mac"], "aa:bb:cc:00:11:22")
        self.assertEqual(net["ssid"], "Home Net 5G")
        self.assertEqual(net["prefix"], 24)

    def test_bssid_is_not_mistaken_for_the_network_name(self):
        net = wifimon.parse_windows_network(self.SCRIPT, "    BSSID : aa:bb\n")
        self.assertIsNone(net["ssid"])

    def test_no_network(self):
        self.assertIsNone(wifimon.parse_windows_network("", ""))

    def test_format_mac(self):
        self.assertEqual(wifimon.format_mac(bytes([0xaa, 0xbb, 0xcc, 0, 1, 2])), "aa:bb:cc:00:01:02")
        self.assertIsNone(wifimon.format_mac(b"\x00" * 6))
        self.assertIsNone(wifimon.format_mac(b"\xff" * 6))
        self.assertIsNone(wifimon.format_mac(b""))

    def test_discover_keeps_only_addresses_that_answered(self):
        macs = {"10.0.0.1": "aa:00:00:00:00:01"}
        with mock.patch.object(wifimon, "send_arp", side_effect=macs.get):
            seen = wifimon.windows_discover(["10.0.0.1", "10.0.0.2"])
        self.assertEqual(seen, {"aa:00:00:00:00:01": "10.0.0.1"})


if __name__ == "__main__":
    unittest.main()
