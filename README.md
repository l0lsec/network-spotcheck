# Network Spotcheck

A macOS/Linux command-line tool that inventories every active network connection on your machine and checks each remote IP against real threat intelligence — no IP is assumed safe just because it belongs to a known cloud provider.

## Why

Malicious infrastructure routinely lives on AWS, Azure, GCP, and behind Cloudflare. Knowing the *provider* tells you nothing about whether the traffic is legitimate. This tool queries every IP against actual reputation databases so you get a real answer.

## What It Does

1. **Captures all established connections** via `lsof` — process name, PID, remote IP, port.
2. **Flags non-standard ports** — anything outside 443, 80, 53, etc.
3. **Resolves reverse DNS** for every remote IP.
4. **Queries threat intelligence APIs** — VirusTotal and AbuseIPDB — for each IP.
5. **Flags IPs** with non-zero malicious/abuse scores.
6. **Tracks sessions** so you can spread a large scan across multiple days without re-checking IPs.

## Requirements

- macOS or Linux (uses `lsof`, `dig`, `curl`)
- Python 3 (for JSON parsing — already on macOS)
- **Optional:** Free API keys for active threat lookups:
  - [VirusTotal](https://www.virustotal.com) — free tier: 4 req/min, 500/day, 15.5K/month
  - [AbuseIPDB](https://www.abuseipdb.com) — free tier: 1,000 req/day

Without API keys the tool still collects connections, resolves reverse DNS, flags unusual ports, and generates clickable VirusTotal links for manual review.

## Install

```bash
git clone https://github.com/<you>/network-spotcheck.git
cd network-spotcheck
chmod +x network_spotcheck.sh
```

Optionally add your API keys to your shell profile:

```bash
export VIRUSTOTAL_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"
```

## Usage

```
./network_spotcheck.sh [OPTIONS]
```

### Modes

| Flag | Description |
|------|-------------|
| `--mode free` | **(default)** Respects VT free-tier limits: 4 req/min, 500/day, 15.5K/month. Tracks quota across runs. |
| `--mode premium` | No rate limiting. Uses your VT premium license at full speed. |
| `--mode passive` | No API calls at all. Collects connections, reverse DNS, and port analysis only. |

### Session & Resume

Every run creates a session that persists your progress to `~/.spotcheck_sessions/`. If the scan is interrupted (Ctrl+C, quota exhaustion, etc.), pick up exactly where you left off:

```bash
# Start a named scan
./network_spotcheck.sh --session my_audit

# ... quota runs out or you Ctrl+C ...

# Resume later (auto-finds the latest incomplete session)
./network_spotcheck.sh --resume

# Or resume a specific session by name
./network_spotcheck.sh --resume my_audit

# List all sessions with status and progress
./network_spotcheck.sh --sessions
```

Session states:
- `in_progress` — currently running
- `interrupted` — stopped by Ctrl+C (safe to resume)
- `quota_paused` — VT daily quota hit (resume tomorrow)
- `complete` — all IPs checked

### Filtering

| Flag | Description |
|------|-------------|
| `--vt-only` | Skip AbuseIPDB, only query VirusTotal |
| `--abuse-only` | Skip VirusTotal, only query AbuseIPDB |

### Quota Management

```bash
# Check remaining VT quota
./network_spotcheck.sh --quota

# Reset the quota tracker
./network_spotcheck.sh --reset-quota
```

## Example: Full Daily Scan

Run the maximum 500 VT lookups per day until every IP is checked:

```bash
# Day 1 — start the scan
./network_spotcheck.sh --session weekly_check

# Script auto-pauses when daily quota is exhausted.
# Output: "Resume tomorrow with: ./network_spotcheck.sh --resume"

# Day 2 — pick up where you left off
./network_spotcheck.sh --resume

# Repeat until session shows [complete]
```

## Output

The tool prints a live table to the terminal and saves a full report to `/tmp/network_spotcheck_*.txt`.

```
  #    IP                 REVERSE DNS                       PROCS     ABUSEIPDB            VIRUSTOTAL
  -    --                 -----------                       -----     ---------            ----------
  1    104.18.18.125      (no PTR)                          Cursor    0%|0 reports         0m/0s/73h
  2    54.205.168.143     ec2-54-205-168-143.amazonaws.com  Cursor    12%|3 reports        2m/1s/68h      [FLAGGED]
  ...
```

When a session finishes, a merged summary of all results is printed, with a dedicated section for any flagged IPs.

## File Locations

| Path | Purpose |
|------|---------|
| `~/.spotcheck_sessions/` | Session data (IP lists, results, metadata) |
| `~/.vt_quota` | Persistent VT free-tier quota tracker |
| `/tmp/network_spotcheck_*.txt` | Per-run text reports |

## License

MIT
