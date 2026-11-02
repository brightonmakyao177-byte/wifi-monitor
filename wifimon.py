#!/usr/bin/env python3
"""Track how many devices are on your Wi-Fi, and when each one was there.

Needs no root and no third-party packages. Each scan nudges every address on
the subnet with a UDP packet, which makes the kernel send ARP requests, then
reads back which neighbours answered. On Windows, which has no equivalent way
to read how recently a neighbour answered, it sends the ARP requests directly.
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

WINDOWS = sys.platform == "win32"
FROZEN = getattr(sys, "frozen", False)  # Running from the packaged .exe.
HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
if WINDOWS:
    DEFAULT_DB = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "WiFiMonitor/devices.db"
else:
    DEFAULT_DB = Path.home() / ".local/share/wifi-monitor/devices.db"
OUI_FILE = Path("/usr/share/ieee-data/oui.csv")

# How long ARP takes to settle after a sweep: the kernel waits 5s before
# re-probing a stale entry, then makes 3 probes one second apart.
SETTLE_SECONDS = 9
SWEEP_PASSES = 2
# The longest an entry can stay REACHABLE, and so go unprobed (1.5 x the
# kernel's default base_reachable_time of 30s).
MAX_REACHABLE_SECONDS = 45
SCAN_RETENTION_DAYS = 180
HOSTNAME_RETRY_SECONDS = 3600
WINDOWS_ARP_THREADS = 64  # An unanswered SendARP blocks its thread for a few seconds.

WINDOWS_NETWORK_SCRIPT = """
$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -ne '0.0.0.0' } |
    Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
if (!$r) { exit 1 }
$a = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $r.ifIndex |
    Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
if (!$a) { exit 1 }
$n = Get-NetAdapter -InterfaceIndex $r.ifIndex
@{ gateway = $r.NextHop; ip = $a.IPAddress; prefix = $a.PrefixLength; mac = $n.MacAddress; dev = $n.Name } |
    ConvertTo-Json -Compress
"""
MAX_COUNT_POINTS = 720

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    custom_name TEXT,
    is_self INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    mac TEXT NOT NULL REFERENCES devices(mac),
    start REAL NOT NULL,
    end REAL NOT NULL,
    open INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS sessions_end ON sessions(end);
CREATE INDEX IF NOT EXISTS sessions_open ON sessions(open);
CREATE TABLE IF NOT EXISTS scans (ts REAL PRIMARY KEY, online INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def connect(db_path):
    db = sqlite3.connect(db_path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    return db


def get_meta(db, key):
    row = db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_meta(db, key, value):
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))


def gap_threshold(interval, grace):
    """A silence longer than this means the monitor itself wasn't running."""
    return max(grace, 3 * interval)


def record_scan(db, ts, seen, interval, grace, self_mac=None):
    """Store one scan. `seen` maps MAC to IP. Returns MACs seen for the first time."""
    with db:
        last = db.execute("SELECT MAX(ts) AS ts FROM scans").fetchone()["ts"]
        if last is not None and ts - last > gap_threshold(interval, grace):
            # We were asleep or stopped, so we can't claim anyone stayed online.
            db.execute("UPDATE sessions SET open = 0 WHERE open = 1")

        new = []
        for mac, ip in seen.items():
            known = db.execute("SELECT 1 FROM devices WHERE mac = ?", (mac,)).fetchone()
            if known:
                db.execute("UPDATE devices SET last_seen = ?, ip = ? WHERE mac = ?", (ts, ip, mac))
            else:
                new.append(mac)
                db.execute(
                    "INSERT INTO devices (mac, first_seen, last_seen, ip, is_self) VALUES (?, ?, ?, ?, ?)",
                    (mac, ts, ts, ip, int(mac == self_mac)),
                )
            updated = db.execute("UPDATE sessions SET end = ? WHERE mac = ? AND open = 1", (ts, mac))
            if updated.rowcount == 0:
                db.execute("INSERT INTO sessions (mac, start, end) VALUES (?, ?, ?)", (mac, ts, ts))

        # A device stays "online" through short silences: phones often sleep
        # through a scan. The session's end is still the last time it answered.
        db.execute("UPDATE sessions SET open = 0 WHERE open = 1 AND ? - end > ?", (ts, grace))
        online = db.execute("SELECT COUNT(*) AS n FROM sessions WHERE open = 1").fetchone()["n"]
        db.execute("INSERT OR REPLACE INTO scans (ts, online) VALUES (?, ?)", (ts, online))
    return new


def run(*cmd, timeout=5):
    # Without this, each command flashes a console window on Windows.
    flags = {"creationflags": subprocess.CREATE_NO_WINDOW} if WINDOWS else {}
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              errors="replace", stdin=subprocess.DEVNULL, **flags)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return done.stdout if done.returncode == 0 else ""


def network_info():
    """The current default network, or None when there isn't one."""
    if WINDOWS:
        return windows_network_info()
    routes = json.loads(run("ip", "-j", "-4", "route", "show", "default") or "[]")
    routes = [r for r in routes if r.get("gateway") and r.get("dev")]
    if not routes:
        return None
    route = min(routes, key=lambda r: r.get("metric", 0))
    dev = route["dev"]
    links = json.loads(run("ip", "-j", "-4", "addr", "show", "dev", dev) or "[]")
    addrs = [a for link in links for a in link.get("addr_info", [])]
    if not addrs:
        return None
    try:
        mac = Path(f"/sys/class/net/{dev}/address").read_text().strip().lower()
    except OSError:
        return None
    return {
        "dev": dev,
        "gateway": route["gateway"],
        "ip": addrs[0]["local"],
        "prefix": addrs[0]["prefixlen"],
        "mac": mac,
        "ssid": run("iwgetid", "-r", dev).strip() or None,
    }


def parse_windows_network(script_output, netsh_output):
    try:
        info = json.loads(script_output)
    except ValueError:
        return None
    if not all(info.get(key) for key in ("gateway", "ip", "prefix", "mac", "dev")):
        return None
    # The "SSID" label isn't translated, unlike netsh's other labels. "BSSID" is a different line.
    ssid = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", netsh_output, flags=re.M)
    return {
        "dev": info["dev"],
        "gateway": info["gateway"],
        "ip": info["ip"],
        "prefix": info["prefix"],
        "mac": info["mac"].lower().replace("-", ":"),
        "ssid": ssid.group(1) if ssid else None,
    }


def windows_network_info():
    script = run("powershell", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_NETWORK_SCRIPT, timeout=20)
    # Some Windows versions refuse netsh without location access. We just lose the name.
    return parse_windows_network(script, run("netsh", "wlan", "show", "interfaces"))


def format_mac(raw):
    """A MAC string from raw bytes, or None for the all-zero and broadcast placeholders."""
    if len(raw) != 6 or raw in (b"\x00" * 6, b"\xff" * 6):
        return None
    return ":".join(f"{byte:02x}" for byte in raw)


def send_arp(ip):
    """Ask one address for its MAC using the Windows API, which needs no admin rights."""
    import ctypes

    buffer = (ctypes.c_ubyte * 8)()
    length = ctypes.c_ulong(6)
    # IPAddr holds the address in network byte order, so keep the bytes as they are.
    target = struct.unpack("=L", socket.inet_aton(ip))[0]
    result = ctypes.windll.iphlpapi.SendARP(ctypes.c_ulong(target), ctypes.c_ulong(0), buffer, ctypes.byref(length))
    return format_mac(bytes(buffer[: length.value])) if result == 0 else None


def windows_discover(targets):
    with ThreadPoolExecutor(WINDOWS_ARP_THREADS) as pool:
        macs = pool.map(send_arp, targets)
    return {mac: ip for ip, mac in zip(targets, macs) if mac}


def discover(net):
    """MAC to IP for everything that answered on this network."""
    targets = sweep_targets(net["ip"], net["prefix"])
    if WINDOWS:
        return windows_discover(targets)
    sweep_started = time.time()
    sweep(targets)
    time.sleep(SETTLE_SECONDS)
    return read_neighbours(net["dev"], time.time() - sweep_started)


def sweep_targets(ip, prefix):
    # Sweeping more than a /24 would be slow and noisy, so stay near our address.
    network = ipaddress.ip_network(f"{ip}/{max(prefix, 24)}", strict=False)
    return [str(host) for host in network.hosts() if str(host) != ip]


def sweep(targets):
    """Prompt the kernel to ARP for each address. The packets' content is irrelevant."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _ in range(SWEEP_PASSES):
            for target in targets:
                try:
                    sock.sendto(b"", (target, 9))
                except OSError:
                    pass  # An unreachable host just won't appear in the results.
                time.sleep(0.004)


def read_neighbours(dev, scan_seconds):
    """MAC to IP for neighbours that answered during, or just before, this scan."""
    seen = {}
    for entry in json.loads(run("ip", "-s", "-j", "-4", "neigh", "show", "dev", dev) or "[]"):
        # Don't go by the entry's state. The kernel won't re-probe an entry that
        # is REACHABLE when the sweep starts, and it can turn STALE before we
        # read it, even though the device is there. Its age is reliable.
        answered = entry.get("confirmed", float("inf")) <= scan_seconds + MAX_REACHABLE_SECONDS
        if answered and entry.get("lladdr") and "FAILED" not in entry.get("state", []):
            seen[entry["lladdr"].lower()] = entry["dst"]
    return seen


def load_vendors():
    vendors = {}
    # The packaged app ships its own list, because Windows doesn't have one.
    source = HERE / "oui.csv" if (HERE / "oui.csv").exists() else OUI_FILE
    try:
        with source.open(newline="", encoding="utf-8", errors="replace") as handle:
            for row in csv.DictReader(handle):
                vendors[row["Assignment"].lower()] = row["Organization Name"].strip()
    except (OSError, KeyError):
        pass
    return vendors


def is_private_mac(mac):
    """Phones and laptops often make up a random address for each network."""
    return bool(int(mac[:2], 16) & 0b10)


def reverse_dns(ip, timeout=2):
    found = []

    def work():
        try:
            found.append(socket.gethostbyaddr(ip)[0])
        except OSError:
            pass

    # gethostbyaddr has no timeout of its own and can hang for a long time.
    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(timeout)
    return found[0] if found else ""


def lookup_hostname(ip):
    if WINDOWS:
        name = reverse_dns(ip)
    else:
        out = run("getent", "hosts", ip, timeout=2).split()
        name = out[1] if len(out) > 1 else ""
        if not name:
            out = run("avahi-resolve-address", ip, timeout=2).split()
            name = out[1] if len(out) > 1 else ""
    if name == "_gateway":  # systemd-resolved's name for the default gateway.
        return "Router"
    name = re.sub(r"\.(local|lan|home|localdomain)\.?$", "", name.rstrip("."), flags=re.I)
    # Names come from other devices on the network, so don't trust their shape.
    return name[:64] if re.fullmatch(r"[\w.-]+", name) and name != ip else None


class Scanner(threading.Thread):
    def __init__(self, db_path, interval, grace, adopt_network=False):
        super().__init__(daemon=True)
        self.db_path = db_path
        self.interval = interval
        self.grace = grace
        self.adopt_network = adopt_network
        self.vendors = load_vendors()
        self.hostname_tried = {}
        self.status = {"state": "starting", "ssid": None, "message": "Running the first scan…"}

    def run(self):
        db = connect(self.db_path)
        next_prune = 0
        while True:
            started = time.time()
            try:
                self.scan_once(db)
                if started >= next_prune:
                    with db:
                        db.execute("DELETE FROM scans WHERE ts < ?", (started - SCAN_RETENTION_DAYS * 86400,))
                    next_prune = started + 86400
            except Exception as error:  # Keep monitoring through one bad scan.
                self.status = {"state": "error", "ssid": self.status.get("ssid"), "message": f"Scan failed: {error}"}
                print(f"scan failed: {error}", flush=True)
            time.sleep(max(1, self.interval - (time.time() - started)))

    def scan_once(self, db):
        net = network_info()
        if net is None:
            self.status = {"state": "offline", "ssid": None, "message": "This computer isn't connected to a network."}
            return

        seen = discover(net)

        # The gateway always answers ARP. If it didn't, the scan itself failed
        # (say, a Wi-Fi blip) and shouldn't be read as everyone leaving.
        gateway_mac = next((mac for mac, ip in seen.items() if ip == net["gateway"]), None)
        if gateway_mac is None:
            self.status = {"state": "offline", "ssid": net["ssid"], "message": "Couldn't reach the router, so this scan was skipped."}
            return

        home = get_meta(db, "gateway_mac")
        if home is None or self.adopt_network:
            with db:
                set_meta(db, "gateway_mac", gateway_mac)
                set_meta(db, "ssid", net["ssid"] or "")
            self.adopt_network = False
        elif home != gateway_mac:
            self.status = {
                "state": "elsewhere",
                "ssid": net["ssid"],
                "message": f"Paused: this computer is on another network, not {get_meta(db, 'ssid') or 'the monitored one'}.",
            }
            return

        seen[net["mac"]] = net["ip"]
        ts = time.time()
        new = record_scan(db, ts, seen, self.interval, self.grace, self_mac=net["mac"])
        self.identify(db, seen, new, ts)
        self.status = {"state": "ok", "ssid": net["ssid"], "message": ""}
        print(f"{time.strftime('%F %T')} answered={len(seen)} new={len(new)}", flush=True)

    def identify(self, db, seen, new, now):
        for mac in new:
            vendor = self.vendors.get(mac.replace(":", "")[:6])
            with db:
                db.execute("UPDATE devices SET vendor = ? WHERE mac = ?", (vendor, mac))
            print(f"new device: {mac} {seen[mac]} {vendor or ''}", flush=True)
        for mac, ip in seen.items():
            if now - self.hostname_tried.get(mac, 0) < HOSTNAME_RETRY_SECONDS:
                continue
            row = db.execute("SELECT hostname FROM devices WHERE mac = ?", (mac,)).fetchone()
            if row["hostname"]:
                continue
            self.hostname_tried[mac] = now
            hostname = lookup_hostname(ip)
            if hostname:
                with db:
                    db.execute("UPDATE devices SET hostname = ? WHERE mac = ?", (hostname, mac))


def build_state(db, hours, interval, grace, status, now=None):
    now = now or time.time()
    since = now - hours * 3600
    threshold = gap_threshold(interval, grace)

    last_scan = db.execute("SELECT MAX(ts) AS ts FROM scans").fetchone()["ts"]
    fresh = last_scan is not None and now - last_scan <= threshold

    sessions = {}
    rows = db.execute("SELECT mac, start, end, open FROM sessions WHERE end >= ? ORDER BY start", (since,))
    for row in rows:
        end = last_scan if row["open"] and fresh else row["end"]
        sessions.setdefault(row["mac"], []).append([max(row["start"], since), end])

    online_macs = set()
    if fresh:
        online_macs = {r["mac"] for r in db.execute("SELECT mac FROM sessions WHERE open = 1")}

    devices = []
    for row in db.execute("SELECT * FROM devices"):
        device = dict(row)
        device["private"] = is_private_mac(row["mac"])
        device["online"] = row["mac"] in online_macs
        device["sessions"] = sessions.get(row["mac"], [])
        device["seconds"] = sum(end - start for start, end in device["sessions"])
        devices.append(device)
    devices.sort(key=lambda d: (not d["online"], -d["last_seen"]))

    bucket = max(hours * 3600 / MAX_COUNT_POINTS, 1)
    counts = [
        [r["ts"], r["online"]]
        for r in db.execute(
            "SELECT MIN(ts) AS ts, MAX(online) AS online FROM scans WHERE ts >= ? "
            "GROUP BY CAST((ts - ?) / ? AS INTEGER) ORDER BY ts",
            (since, since, bucket),
        )
    ]

    gaps = []
    previous = None
    # Include the scan just before the range, so a gap spanning its start is found.
    before = db.execute("SELECT MAX(ts) AS ts FROM scans WHERE ts < ?", (since,)).fetchone()["ts"]
    for row in db.execute("SELECT ts FROM scans WHERE ts >= ? ORDER BY ts", (since,)):
        if previous is None:
            previous = before if before is not None else since
            if before is None and row["ts"] - since <= threshold:
                previous = row["ts"]
        if row["ts"] - previous > threshold:
            gaps.append([max(previous, since), row["ts"]])
        previous = row["ts"]
    if previous is None:
        gaps.append([since, now])
    elif now - previous > threshold:
        gaps.append([previous, now])

    peak = db.execute(
        "SELECT ts, online FROM scans WHERE ts >= ? ORDER BY online DESC, ts DESC LIMIT 1", (since,)
    ).fetchone()

    return {
        "now": now,
        "since": since,
        "hours": hours,
        "interval": interval,
        "grace": grace,
        "status": status,
        "ssid": status.get("ssid") or get_meta(db, "ssid") or None,
        "last_scan": last_scan,
        "online": len(online_macs) if fresh else None,
        "peak": {"ts": peak["ts"], "online": peak["online"]} if peak else None,
        "active": sum(1 for d in devices if d["sessions"]),
        "new": sum(1 for d in devices if d["first_seen"] >= since),
        "devices": devices,
        "counts": counts,
        "gaps": gaps,
    }


def make_handler(db_path, scanner, interval, grace):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send_body(self, code, body, content_type="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, code, value):
            self.send_body(code, json.dumps(value).encode())

        def host_allowed(self):
            # Stops other websites reaching this server through DNS rebinding.
            host = self.headers.get("Host", "").rsplit(":", 1)[0].strip("[]")
            return host in ("localhost", "127.0.0.1", "::1") or host == self.server.server_address[0]

        def do_GET(self):
            if not self.host_allowed():
                return self.send_json(403, {"error": "forbidden"})
            url = urlparse(self.path)
            if url.path == "/":
                return self.send_body(200, (HERE / "dashboard.html").read_bytes(), "text/html; charset=utf-8")
            if url.path == "/api/state":
                try:
                    hours = float(parse_qs(url.query).get("hours", ["24"])[0])
                except ValueError:
                    return self.send_json(400, {"error": "bad hours"})
                hours = min(max(hours, 1), SCAN_RETENTION_DAYS * 24)
                status = scanner.status if scanner else {"state": "history", "ssid": None, "message": ""}
                db = connect(db_path)
                try:
                    return self.send_json(200, build_state(db, hours, interval, grace, status))
                finally:
                    db.close()
            self.send_json(404, {"error": "not found"})

        def do_POST(self):
            # Requiring JSON makes a cross-site form or fetch fail its preflight.
            if not self.host_allowed() or self.headers.get("Content-Type") != "application/json":
                return self.send_json(403, {"error": "forbidden"})
            if urlparse(self.path).path == "/api/quit":
                self.send_json(200, {"ok": True})
                # shutdown() waits for the server loop, so it can't run on this thread's request.
                return threading.Thread(target=self.server.shutdown, daemon=True).start()
            match = re.fullmatch(r"/api/devices/([0-9a-f:]{17})", urlparse(self.path).path)
            if not match:
                return self.send_json(404, {"error": "not found"})
            try:
                length = min(int(self.headers.get("Content-Length", 0)), 4096)
                name = json.loads(self.rfile.read(length)).get("name")
            except (ValueError, AttributeError):
                return self.send_json(400, {"error": "bad request"})
            name = str(name or "").strip()[:64] or None
            db = connect(db_path)
            try:
                with db:
                    db.execute("UPDATE devices SET custom_name = ? WHERE mac = ?", (name, match.group(1)))
            finally:
                db.close()
            self.send_json(200, {"ok": True})

    return Handler


def stop_running(port):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/quit", data=b"{}", headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(request, timeout=5).close()
    except OSError:
        print("The monitor wasn't running.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="history database (default: %(default)s)")
    parser.add_argument("--port", type=int, default=8765, help="dashboard port (default: %(default)s)")
    parser.add_argument("--host", default="127.0.0.1", help="dashboard address (default: this computer only)")
    parser.add_argument("--interval", type=int, default=60, help="seconds between scans (default: %(default)s)")
    parser.add_argument("--grace", type=int, default=300,
                        help="seconds a device may stay silent before it counts as gone (default: %(default)s)")
    parser.add_argument("--adopt-network", action="store_true", help="make the current network the monitored one")
    parser.add_argument("--no-scan", action="store_true", help="only show existing history")
    parser.add_argument("--background", action="store_true", help="packaged app: don't open the dashboard on start")
    parser.add_argument("--stop", action="store_true", help="stop the monitor that's already running")
    args = parser.parse_args()
    args.interval = max(args.interval, SETTLE_SECONDS + 6)

    if args.stop:
        return stop_running(args.port)

    args.db.parent.mkdir(parents=True, exist_ok=True)
    if sys.stdout is None:  # The packaged app has no console, so keep its output somewhere.
        sys.stdout = sys.stderr = open(args.db.parent / "monitor.log", "w", encoding="utf-8", buffering=1)
    connect(args.db).close()

    url = f"http://{args.host}:{args.port}"
    # On Windows this option would let a second copy share the port without an error.
    ThreadingHTTPServer.allow_reuse_address = not WINDOWS
    holder = {}
    try:
        server = ThreadingHTTPServer((args.host, args.port), lambda *a: holder["handler"](*a))
    except OSError:
        # Already running, most likely: double-clicking the app again just shows it.
        if FROZEN and not args.background:
            webbrowser.open(url)
            return
        raise

    scanner = None
    if not args.no_scan:
        scanner = Scanner(args.db, args.interval, args.grace, args.adopt_network)
        scanner.start()

    holder["handler"] = make_handler(args.db, scanner, args.interval, args.grace)
    print(f"Dashboard: {url}  History: {args.db}", flush=True)
    if FROZEN and not args.background:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
