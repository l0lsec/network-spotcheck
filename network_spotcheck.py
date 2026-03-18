#!/usr/bin/env python3
"""Network Connection Spot Check.

Queries every remote IP against real threat intelligence APIs.
Does NOT assume any IP is safe based on provider ownership alone.
"""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: requests\n  pip install requests")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# =============================================================================
# Constants
# =============================================================================

STANDARD_PORTS = frozenset(
    [443, 80, 53, 8080, 8443, 5228, 5223, 993, 587, 465, 143]
)

VT_FREE_RATE = 4
VT_FREE_DELAY = 15
VT_FREE_DAILY_MAX = 500
VT_FREE_MONTHLY_MAX = 15500

VT_QUOTA_FILE = Path.home() / ".vt_quota"
SESSION_DIR = Path.home() / ".spotcheck_sessions"
SCRIPT_DIR = Path(__file__).resolve().parent

PRIVATE_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
)

# =============================================================================
# Output helpers
# =============================================================================

console = Console(highlight=False) if RICH_AVAILABLE else None


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


class _Colors:
    RED = "\033[0;31m"
    YLW = "\033[0;33m"
    GRN = "\033[0;32m"
    CYN = "\033[0;36m"
    DIM = "\033[2m"
    BLD = "\033[1m"
    RST = "\033[0m"


C = _Colors


def out(msg: str = "", *, report: list[str] | None = None) -> None:
    print(msg)
    if report is not None:
        report.append(_strip_ansi(msg))


def _strip_ansi(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


# =============================================================================
# Quota tracker  (same file format as bash: count|count|day_of_year|month)
# =============================================================================

class QuotaTracker:
    def __init__(self) -> None:
        self.day_count = 0
        self.month_count = 0
        self._last_day = ""
        self._last_month = ""
        self._load()

    def _load(self) -> None:
        if not VT_QUOTA_FILE.exists():
            self._reset_file()
        parts = VT_QUOTA_FILE.read_text().strip().split("|")
        if len(parts) < 4:
            self._reset_file()
            parts = VT_QUOTA_FILE.read_text().strip().split("|")
        self.day_count = int(parts[0])
        self.month_count = int(parts[1])
        self._last_day = parts[2]
        self._last_month = parts[3]

        today_day = time.strftime("%j")
        today_month = time.strftime("%m")
        if self._last_month != today_month:
            self.month_count = 0
            self.day_count = 0
            self._last_month = today_month
            self._last_day = today_day
        elif self._last_day != today_day:
            self.day_count = 0
            self._last_day = today_day

    def _reset_file(self) -> None:
        VT_QUOTA_FILE.write_text(
            f"0|0|{time.strftime('%j')}|{time.strftime('%m')}"
        )

    def save(self) -> None:
        VT_QUOTA_FILE.write_text(
            f"{self.day_count}|{self.month_count}|{self._last_day}|{self._last_month}"
        )

    def increment(self) -> None:
        self.day_count += 1
        self.month_count += 1
        self.save()

    @property
    def daily_remaining(self) -> int:
        return VT_FREE_DAILY_MAX - self.day_count

    @property
    def monthly_remaining(self) -> int:
        return VT_FREE_MONTHLY_MAX - self.month_count

    def can_query(self) -> bool:
        return self.daily_remaining > 0 and self.monthly_remaining > 0

    def show(self) -> None:
        print()
        print("  VirusTotal Free Tier Quota Tracker")
        print("  -----------------------------------")
        print(f"  Daily:   {self.day_count} / {VT_FREE_DAILY_MAX}  ({self.daily_remaining} remaining)")
        print(f"  Monthly: {self.month_count} / {VT_FREE_MONTHLY_MAX}  ({self.monthly_remaining} remaining)")
        print(f"  Tracker: {VT_QUOTA_FILE}")
        print()


# =============================================================================
# Session management
# =============================================================================

class Connection(NamedTuple):
    proc: str
    pid: str
    remote: str
    port: str


class IPResult(NamedTuple):
    ip: str
    rdns: str
    procs: str
    abuse: str
    vt: str
    flag: str
    ts: str


class Session:
    def __init__(self, name: str) -> None:
        self.name = name
        self.path = SESSION_DIR / name
        self.ips: list[str] = []
        self.connections: list[Connection] = []
        self.results: list[IPResult] = []
        self.mode = "free"
        self.status = "in_progress"

    @property
    def meta_path(self) -> Path:
        return self.path / "meta.txt"

    @property
    def results_path(self) -> Path:
        return self.path / "results.jsonl"

    def create(self, connections: list[Connection], unique_ips: list[str], mode: str) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        self.connections = connections
        self.ips = unique_ips
        self.mode = mode
        (self.path / "connections.txt").write_text(
            "\n".join(f"{c.proc}|{c.pid}|{c.remote}|{c.port}" for c in connections)
        )
        (self.path / "ips.txt").write_text("\n".join(unique_ips))
        self.meta_path.write_text(
            f"status=in_progress\nmode={mode}\ncreated={_ts()}\nupdated={_ts()}\n"
        )
        self.results_path.touch()

    def load(self) -> None:
        conn_file = self.path / "connections.txt"
        if conn_file.exists():
            self.connections = []
            for line in conn_file.read_text().strip().splitlines():
                parts = line.split("|")
                if len(parts) >= 4:
                    self.connections.append(Connection(*parts[:4]))

        ips_file = self.path / "ips.txt"
        if ips_file.exists():
            self.ips = [l for l in ips_file.read_text().strip().splitlines() if l]

        if self.results_path.exists():
            self.results = []
            for line in self.results_path.read_text().strip().splitlines():
                if not line:
                    continue
                d = json.loads(line)
                self.results.append(IPResult(
                    ip=d["ip"], rdns=d["rdns"], procs=d["procs"],
                    abuse=d["abuse"], vt=d["vt"], flag=d["flag"], ts=d["ts"],
                ))

        if self.meta_path.exists():
            for line in self.meta_path.read_text().splitlines():
                if line.startswith("mode="):
                    self.mode = line.split("=", 1)[1]
                elif line.startswith("status="):
                    self.status = line.split("=", 1)[1]

    def checked_ips(self) -> set[str]:
        return {r.ip for r in self.results}

    def save_result(self, result: IPResult) -> None:
        self.results.append(result)
        with self.results_path.open("a") as f:
            f.write(json.dumps(result._asdict()) + "\n")
        self._update_ts()

    def _update_ts(self) -> None:
        if self.meta_path.exists():
            text = self.meta_path.read_text()
            text = re.sub(r"^updated=.*$", f"updated={_ts()}", text, flags=re.MULTILINE)
            self.meta_path.write_text(text)

    def set_status(self, status: str) -> None:
        self.status = status
        if self.meta_path.exists():
            text = self.meta_path.read_text()
            text = re.sub(r"^status=.*$", f"status={status}", text, flags=re.MULTILINE)
            self.meta_path.write_text(text)
            self._update_ts()


def list_sessions() -> None:
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    print()
    print("  Saved sessions:")
    print("  ----------------")
    found = False
    for meta in sorted(SESSION_DIR.glob("*/meta.txt")):
        found = True
        sdir = meta.parent
        name = sdir.name
        status = "unknown"
        for line in meta.read_text().splitlines():
            if line.startswith("status="):
                status = line.split("=", 1)[1]
        ips_file = sdir / "ips.txt"
        results_file = sdir / "results.jsonl"
        total = len(ips_file.read_text().strip().splitlines()) if ips_file.exists() else 0
        checked = len([l for l in results_file.read_text().strip().splitlines() if l]) if results_file.exists() else 0
        color = C.GRN if status == "complete" else C.YLW
        print(f"  {name:<30} {color}[{status}]{C.RST}  {checked}/{total} IPs checked")
    if not found:
        print("  (none)")
    print()


def find_latest_incomplete() -> str | None:
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    latest = None
    for meta in sorted(SESSION_DIR.glob("*/meta.txt")):
        for line in meta.read_text().splitlines():
            if line.startswith("status=") and line.split("=", 1)[1] != "complete":
                latest = meta.parent.name
    return latest


# =============================================================================
# Allowlist
# =============================================================================

class AllowlistRule(NamedTuple):
    proc_pattern: str
    rdns_pattern: str


def load_allowlist(path: Path) -> list[AllowlistRule]:
    if not path.exists():
        return []
    rules: list[AllowlistRule] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s*\|\s*", line, maxsplit=1)
        if len(parts) == 2:
            rules.append(AllowlistRule(parts[0], parts[1]))
    return rules


def show_allowlist(rules: list[AllowlistRule], path: Path) -> None:
    print()
    print(f"  Allowlist: {path}")
    print("  ---------------------------")
    if not rules:
        print("  (empty or not found)")
    else:
        print()
        print(f"  {C.BLD}{'PROCESS':<20} {'RDNS PATTERN'}{C.RST}")
        print(f"  {'-------':<20} {'------------'}")
        for r in rules:
            print(f"  {r.proc_pattern:<20} {r.rdns_pattern}")
    print()
    print("  Safety rules (always enforced):")
    print("    - IPs with no reverse DNS are NEVER skipped")
    print("    - Non-standard ports are NEVER skipped")
    print("    - Both process AND rDNS must match")
    print()


def _match_glob(pattern: str, string: str) -> bool:
    return fnmatch.fnmatch(string.lower(), pattern.lower())


def is_expected_traffic(
    proc: str, rdns: str, port: str,
    rules: list[AllowlistRule],
) -> bool:
    if rdns == "(no PTR)":
        return False
    try:
        if int(port) not in STANDARD_PORTS:
            return False
    except ValueError:
        return False
    for rule in rules:
        if _match_glob(rule.proc_pattern, proc) and _match_glob(rule.rdns_pattern, rdns):
            return True
    return False


# =============================================================================
# Connection collector
# =============================================================================

def collect_connections() -> list[Connection]:
    try:
        raw = subprocess.run(
            ["lsof", "-i", "-P", "-n"],
            capture_output=True, text=True, timeout=30,
        ).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    seen: set[tuple[str, str, str, str]] = set()
    results: list[Connection] = []
    for line in raw.splitlines():
        if "ESTABLISHED" not in line:
            continue
        fields = line.split()
        if len(fields) < 9:
            continue
        proc = fields[0]
        pid = fields[1]
        conn = fields[8]
        arrow = conn.split("->")
        if len(arrow) < 2:
            continue
        remote_part = arrow[1]
        last_colon = remote_part.rfind(":")
        if last_colon == -1:
            continue
        remote = remote_part[:last_colon]
        port = remote_part[last_colon + 1:]

        try:
            addr = ipaddress.ip_address(remote)
        except ValueError:
            continue
        if any(addr in net for net in PRIVATE_NETWORKS):
            continue

        key = (proc, pid, remote, port)
        if key not in seen:
            seen.add(key)
            results.append(Connection(proc, pid, remote, port))
    return results


# =============================================================================
# DNS / API clients
# =============================================================================

def reverse_dns(ip: str) -> str:
    try:
        raw = subprocess.run(
            ["dig", "+short", "-x", ip],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        result = raw.splitlines()[0].rstrip(".") if raw else ""
    except Exception:
        result = ""
    return result or "(no PTR)"


def check_abuseipdb(ip: str, api_key: str) -> str:
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=10,
        )
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", "?")
        reports = data.get("totalReports", "?")
        return f"{score}%|{reports} reports"
    except Exception:
        return "error"


def check_virustotal(ip: str, api_key: str) -> str:
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        body = resp.json()
        err_code = body.get("error", {}).get("code", "")
        if err_code == "QuotaExceededError":
            return "quota_hit"
        stats = body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        m = stats.get("malicious", 0)
        s = stats.get("suspicious", 0)
        h = stats.get("harmless", 0)
        return f"{m}m/{s}s/{h}h"
    except Exception:
        return "error"


# =============================================================================
# Analysis + main scan flow
# =============================================================================

def _procs_for_ip(connections: list[Connection], ip: str) -> str:
    return ",".join(sorted({c.proc for c in connections if c.remote == ip}))


def _ports_for_ip(connections: list[Connection], ip: str) -> str:
    return ",".join(sorted({c.port for c in connections if c.remote == ip}))


def _connections_for_ip(connections: list[Connection], ip: str) -> list[Connection]:
    return [c for c in connections if c.remote == ip]


def _flag_result(abuse: str, vt: str) -> str:
    flag = ""
    if abuse not in ("--", "error", "expected", "skip"):
        try:
            score = int(abuse.split("%")[0])
            if score > 0:
                flag = "[FLAGGED]"
        except ValueError:
            pass
    if not flag:
        m = re.match(r"^(\d+)m/", _strip_ansi(vt))
        if m and int(m.group(1)) > 0:
            flag = "[FLAGGED]"
    return flag


def run_scan(args: argparse.Namespace) -> None:
    mode: str = args.mode
    abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    skip_vt: bool = args.vt_only is False and args.abuse_only is True
    skip_abuse: bool = args.abuse_only is False and args.vt_only is True

    # More intuitive: --vt-only means skip abuse, --abuse-only means skip vt
    if args.vt_only:
        skip_abuse = True
        skip_vt = False
    elif args.abuse_only:
        skip_vt = True
        skip_abuse = False
    else:
        skip_vt = False
        skip_abuse = False

    allowlist_path = Path(args.allowlist) if args.allowlist else Path(
        os.environ.get("SPOTCHECK_ALLOWLIST", SCRIPT_DIR / "allowlist.conf")
    )
    use_allowlist = not args.no_allowlist
    allowlist_rules = load_allowlist(allowlist_path) if use_allowlist else []

    report_lines: list[str] = []
    report_file = Path(f"/tmp/network_spotcheck_{_now_stamp()}.txt")
    quota = QuotaTracker()

    # --- Resolve session: resume vs new ---
    session: Session
    already_checked: int
    remaining: int

    if args.resume is not None:
        resume_name = args.resume if args.resume != "" else find_latest_incomplete()
        if not resume_name:
            print("  No incomplete sessions to resume.")
            print("  Run --sessions to list available sessions.")
            return
        session = Session(resume_name)
        if not session.path.is_dir():
            print(f"  Session not found: {resume_name}")
            print("  Run --sessions to list available sessions.")
            sys.exit(1)
        session.load()
        mode = session.mode
        session.set_status("in_progress")
        already_checked = len(session.results)
        remaining = len(session.ips) - already_checked

        out("", report=report_lines)
        out("==============================================", report=report_lines)
        out(f"  RESUMING SESSION: {session.name}", report=report_lines)
        out(f"  {datetime.now().strftime('%c')}", report=report_lines)
        out("==============================================", report=report_lines)
        out("", report=report_lines)
        out(f"  Mode: {C.BLD}{mode}{C.RST}", report=report_lines)
        out(f"  Total IPs:     {len(session.ips)}", report=report_lines)
        out(f"  Already done:  {C.GRN}{already_checked}{C.RST}", report=report_lines)
        out(f"  Remaining:     {C.YLW}{remaining}{C.RST}", report=report_lines)

        if mode == "free":
            out(f"  VT daily quota: {C.CYN}{quota.daily_remaining} of {VT_FREE_DAILY_MAX} remaining{C.RST}", report=report_lines)
            est = (remaining * VT_FREE_DELAY + 59) // 60
            out(f"  {C.DIM}Estimated time: ~{est} min for {remaining} remaining IPs{C.RST}", report=report_lines)
        out("", report=report_lines)
    else:
        session_name = args.session or f"scan_{_now_stamp()}"
        session = Session(session_name)

        out("", report=report_lines)
        out("==============================================", report=report_lines)
        out("  NETWORK CONNECTION SPOT CHECK", report=report_lines)
        out(f"  {datetime.now().strftime('%c')}", report=report_lines)
        out("==============================================", report=report_lines)
        out("", report=report_lines)
        out(f"  Mode:    {C.BLD}{mode}{C.RST}", report=report_lines)
        out(f"  Session: {C.BLD}{session_name}{C.RST}", report=report_lines)

        if mode == "free":
            out(f"  VT rate:   {C.CYN}{VT_FREE_RATE} req/min ({VT_FREE_DELAY}s delay){C.RST}", report=report_lines)
            out(f"  VT daily:  {C.CYN}{quota.daily_remaining} of {VT_FREE_DAILY_MAX} remaining{C.RST}", report=report_lines)
            out(f"  VT month:  {C.CYN}{quota.monthly_remaining} of {VT_FREE_MONTHLY_MAX} remaining{C.RST}", report=report_lines)
        elif mode == "premium":
            out(f"  VT rate:   {C.GRN}unlimited (premium){C.RST}", report=report_lines)
        elif mode == "passive":
            out(f"  {C.DIM}API lookups disabled{C.RST}", report=report_lines)

        if abuseipdb_key and not skip_abuse:
            out(f"  AbuseIPDB: {C.GRN}enabled{C.RST}", report=report_lines)
        else:
            out(f"  AbuseIPDB: {C.DIM}disabled{C.RST}", report=report_lines)
        if vt_key and not skip_vt and mode != "passive":
            out(f"  VT:        {C.GRN}enabled{C.RST}", report=report_lines)
        else:
            out(f"  VT:        {C.DIM}disabled{C.RST}", report=report_lines)

        if use_allowlist and allowlist_rules:
            out(f"  Allowlist: {C.GRN}{len(allowlist_rules)} rules{C.RST} ({allowlist_path})", report=report_lines)
        elif not use_allowlist:
            out(f"  Allowlist: {C.YLW}disabled (--no-allowlist){C.RST}", report=report_lines)
        else:
            out(f"  Allowlist: {C.DIM}none found{C.RST}", report=report_lines)
        out("", report=report_lines)

        # [1/4] Collect
        out(f"{C.BLD}[1/4] Collecting established connections...{C.RST}", report=report_lines)
        out("", report=report_lines)

        connections = collect_connections()
        unique_ips = sorted({c.remote for c in connections})
        ip_count = len(unique_ips)

        out(f"  Found {len(connections)} connections to {ip_count} unique remote IPs", report=report_lines)

        session.create(connections, unique_ips, mode)
        already_checked = 0
        remaining = ip_count

        if mode == "free" and vt_key and not skip_vt:
            if ip_count > quota.daily_remaining:
                out("", report=report_lines)
                out(f"  {C.YLW}{ip_count} IPs but only {quota.daily_remaining} VT lookups left today.{C.RST}", report=report_lines)
                out(f"  {C.YLW}Will pause when quota runs out. Resume tomorrow with --resume.{C.RST}", report=report_lines)
            est = (ip_count * VT_FREE_DELAY + 59) // 60
            out(f"  {C.DIM}Estimated time: ~{est} min for {ip_count} IPs{C.RST}", report=report_lines)
        out("", report=report_lines)

        # [2/4] Non-standard ports
        out(f"{C.BLD}[2/4] Checking for non-standard ports...{C.RST}", report=report_lines)
        out("", report=report_lines)
        nonstandard_found = False
        for conn in connections:
            try:
                if int(conn.port) not in STANDARD_PORTS:
                    out(
                        f"  {C.RED}UNUSUAL PORT{C.RST}  {conn.proc} (pid {conn.pid}) -> {conn.remote}:{C.RED}{conn.port}{C.RST}",
                        report=report_lines,
                    )
                    nonstandard_found = True
            except ValueError:
                pass
        if not nonstandard_found:
            out("  All connections use standard ports (443, 80, 53, etc.)", report=report_lines)
        out("", report=report_lines)

    # --- Ctrl+C handler ---
    def _on_interrupt(sig: int, frame: object) -> None:
        print()
        print(f"  {C.YLW}Interrupted! Saving session state...{C.RST}", file=sys.stderr)
        session.set_status("interrupted")
        total = len(session.ips)
        checked = len(session.results)
        print(f"  {C.GRN}Session saved:{C.RST} {checked}/{total} IPs checked", file=sys.stderr)
        print(f"  Resume with: {C.BLD}./network_spotcheck.py --resume{C.RST}", file=sys.stderr)
        print()
        sys.exit(130)

    signal.signal(signal.SIGINT, _on_interrupt)
    signal.signal(signal.SIGTERM, _on_interrupt)

    # =================================================================
    # [3/4] Per-IP analysis
    # =================================================================
    ip_count = len(session.ips)
    checked_set = session.checked_ips()

    out(f"{C.BLD}[3/4] Analyzing remote IPs ({remaining} remaining, {already_checked} already done)...{C.RST}", report=report_lines)
    out("", report=report_lines)

    header = f"  {C.BLD}{'#':<4} {'IP':<18} {'REVERSE DNS':<42} {'PROCS':<14} {'ABUSEIPDB':<20} {'VIRUSTOTAL':<18}{C.RST}"
    sep = f"  {'-':<4} {'--':<18} {'-----------':<42} {'-----':<14} {'---------':<20} {'----------':<18}"
    out(header, report=report_lines)
    out(sep, report=report_lines)

    vt_stopped = False
    checked_this_run = 0

    for ip_idx, ip in enumerate(session.ips, 1):
        if ip in checked_set:
            continue

        checked_this_run += 1
        procs = _procs_for_ip(session.connections, ip)
        rdns = reverse_dns(ip)

        # Allowlist check: skip only if ALL connections to this IP match
        skip_api = False
        if use_allowlist and allowlist_rules:
            ip_conns = _connections_for_ip(session.connections, ip)
            if ip_conns and all(
                is_expected_traffic(c.proc, rdns, c.port, allowlist_rules) for c in ip_conns
            ):
                skip_api = True

        if skip_api:
            result = IPResult(ip, rdns, procs, "expected", "expected", "", _ts())
            session.save_result(result)
            out(
                f"  {ip_idx:<4} {ip:<18} {rdns:<42} {procs:<14} {C.DIM}{'expected':<20}{C.RST} {C.DIM}{'expected':<18}{C.RST}",
                report=report_lines,
            )
            continue

        # AbuseIPDB
        abuse_result = "--"
        if mode != "passive" and abuseipdb_key and not skip_abuse:
            abuse_result = check_abuseipdb(ip, abuseipdb_key)
            if abuse_result == "skip":
                abuse_result = "--"

        # VirusTotal
        vt_result = "--"
        if mode != "passive" and vt_key and not skip_vt and not vt_stopped:
            if mode == "free":
                if quota.can_query():
                    if checked_this_run > 1:
                        for countdown in range(VT_FREE_DELAY, 0, -1):
                            print(
                                f"\r  {C.DIM}[{ip_idx}/{ip_count}] rate limit: {countdown}s ...{C.RST}  ",
                                end="", flush=True, file=sys.stderr,
                            )
                            time.sleep(1)
                        print(f"\r{' ' * 60}\r", end="", flush=True, file=sys.stderr)
                    vt_result = check_virustotal(ip, vt_key)
                    if vt_result == "quota_hit":
                        vt_result = "QUOTA_HIT"
                        vt_stopped = True
                        session.set_status("quota_paused")
                        out(f"\n  {C.RED}VT quota exhausted. Session paused.{C.RST}", report=report_lines)
                        out(f"  {C.CYN}Resume later with: ./network_spotcheck.py --resume{C.RST}", report=report_lines)
                    else:
                        quota.increment()
                else:
                    vt_result = "quota_full"
                    vt_stopped = True
                    session.set_status("quota_paused")
                    out(f"\n  {C.YLW}VT daily quota reached. Session paused.{C.RST}", report=report_lines)
                    out(f"  {C.CYN}Resume tomorrow with: ./network_spotcheck.py --resume{C.RST}", report=report_lines)
            elif mode == "premium":
                vt_result = check_virustotal(ip, vt_key)
                if vt_result == "quota_hit":
                    vt_result = "QUOTA_HIT"
                    vt_stopped = True
                    out(f"\n  {C.RED}VT QuotaExceededError in premium mode. Check license.{C.RST}", report=report_lines)

        if vt_result == "skip":
            vt_result = "--"

        flag = _flag_result(abuse_result, vt_result)
        result = IPResult(ip, rdns, procs, abuse_result, vt_result, flag, _ts())
        session.save_result(result)

        flag_display = f"{C.RED}{flag}{C.RST}" if flag else ""
        vt_display = vt_result
        if vt_result == "QUOTA_HIT":
            vt_display = f"{C.RED}QUOTA HIT{C.RST}"
        elif vt_result == "quota_full":
            vt_display = f"{C.YLW}quota full{C.RST}"

        out(
            f"  {ip_idx:<4} {ip:<18} {rdns:<42} {procs:<14} {abuse_result:<20} {vt_display:<18} {flag_display}",
            report=report_lines,
        )

        if vt_stopped and mode == "free":
            break

    out("", report=report_lines)

    # =================================================================
    # Session status
    # =================================================================
    total_checked = len(session.results)
    if total_checked >= ip_count:
        session.set_status("complete")
        out(f"  {C.GRN}Session complete: all {ip_count} IPs checked.{C.RST}", report=report_lines)
    else:
        out(f"  {C.YLW}Session progress: {total_checked} / {ip_count} IPs checked.{C.RST}", report=report_lines)
        out(f"  {C.CYN}Resume: ./network_spotcheck.py --resume{C.RST}", report=report_lines)

    expected_count = sum(1 for r in session.results if r.vt == "expected")
    if expected_count > 0:
        out(f"  {C.DIM}Allowlist: {expected_count} IPs matched known process+domain rules (API calls saved){C.RST}", report=report_lines)

    if mode == "free" and vt_key and not skip_vt:
        quota = QuotaTracker()
        out(f"  {C.DIM}VT quota: day={quota.daily_remaining}/{VT_FREE_DAILY_MAX}  month={quota.monthly_remaining}/{VT_FREE_MONTHLY_MAX}{C.RST}", report=report_lines)
    out("", report=report_lines)

    # =================================================================
    # [4/4] Merged results
    # =================================================================
    out(f"{C.BLD}[4/4] All results (merged across runs for this session){C.RST}", report=report_lines)
    out("", report=report_lines)

    hdr = f"  {C.BLD}{'IP':<18} {'REVERSE DNS':<42} {'PROCS':<14} {'ABUSEIPDB':<20} {'VIRUSTOTAL':<18}{C.RST}"
    sep2 = f"  {'--':<18} {'-----------':<42} {'-----':<14} {'---------':<20} {'----------':<18}"
    out(hdr, report=report_lines)
    out(sep2, report=report_lines)

    for r in session.results:
        flag_display = f"{C.RED}{r.flag}{C.RST}" if r.flag else ""
        abuse_display = f"{C.DIM}expected{C.RST}" if r.abuse == "expected" else r.abuse
        vt_display = f"{C.DIM}expected{C.RST}" if r.vt == "expected" else r.vt
        out(
            f"  {r.ip:<18} {r.rdns:<42} {r.procs:<14} {abuse_display:<20} {vt_display:<18} {flag_display}",
            report=report_lines,
        )
    out("", report=report_lines)

    # Flagged summary
    flagged = [r for r in session.results if r.flag == "[FLAGGED]"]
    if flagged:
        out(f"  {C.RED}{C.BLD}{len(flagged)} IP(s) FLAGGED by threat intelligence:{C.RST}", report=report_lines)
        for r in flagged:
            out(f"    {C.RED}{r.ip}{C.RST}  abuse={r.abuse}  vt={r.vt}", report=report_lines)
        out("", report=report_lines)
    else:
        out(f"  {C.GRN}No IPs flagged by threat intelligence.{C.RST}", report=report_lines)
        out("", report=report_lines)

    # Manual verification links
    out("==============================================", report=report_lines)
    out("  MANUAL VERIFICATION LINKS", report=report_lines)
    out("==============================================", report=report_lines)
    out("", report=report_lines)
    out("  AbuseIPDB:   https://www.abuseipdb.com/check/<IP>", report=report_lines)
    out("  VirusTotal:  https://www.virustotal.com/gui/ip-address/<IP>", report=report_lines)
    out("  Shodan:      https://www.shodan.io/host/<IP>", report=report_lines)
    out("  GreyNoise:   https://viz.greynoise.io/ip/<IP>", report=report_lines)
    out("", report=report_lines)

    print(f"  Session: {C.BLD}{session.name}{C.RST}  ({session.path}/)")
    print(f"  Report:  {report_file}")
    print()

    report_file.write_text("\n".join(report_lines) + "\n")


# =============================================================================
# CLI
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network_spotcheck",
        description="Query every remote IP against real threat intelligence APIs.",
    )
    p.add_argument(
        "--mode", choices=["free", "premium", "passive"], default="free",
        help="free (default): VT free tier limits. premium: no throttle. passive: no API calls.",
    )
    p.add_argument(
        "--resume", nargs="?", const="", default=None, metavar="NAME",
        help="Resume the most recent incomplete session, or a specific named session.",
    )
    p.add_argument("--session", metavar="NAME", help="Tag this run with a name.")
    p.add_argument("--sessions", action="store_true", help="List all saved sessions and exit.")
    p.add_argument("--no-allowlist", action="store_true", help="Skip the allowlist; check every IP.")
    p.add_argument("--show-allowlist", action="store_true", help="Print the active allowlist rules and exit.")
    p.add_argument("--allowlist", metavar="FILE", help="Use a custom allowlist file.")
    p.add_argument("--vt-only", action="store_true", help="Only run VirusTotal (skip AbuseIPDB).")
    p.add_argument("--abuse-only", action="store_true", help="Only run AbuseIPDB (skip VirusTotal).")
    p.add_argument("--quota", action="store_true", help="Show remaining VT quota and exit.")
    p.add_argument("--reset-quota", action="store_true", help="Reset the quota tracker and exit.")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.sessions:
        list_sessions()
        return

    if args.show_allowlist:
        path = Path(args.allowlist) if args.allowlist else Path(
            os.environ.get("SPOTCHECK_ALLOWLIST", SCRIPT_DIR / "allowlist.conf")
        )
        rules = load_allowlist(path)
        show_allowlist(rules, path)
        return

    if args.quota:
        QuotaTracker().show()
        return

    if args.reset_quota:
        VT_QUOTA_FILE.unlink(missing_ok=True)
        print("  Quota tracker reset.")
        return

    run_scan(args)


if __name__ == "__main__":
    main()
