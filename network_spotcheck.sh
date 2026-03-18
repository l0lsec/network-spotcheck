#!/bin/bash
# =============================================================================
# Network Connection Spot Check
#
# Queries EVERY remote IP against real threat intelligence APIs.
# Does NOT assume any IP is safe based on provider ownership alone.
#
# Usage:
#   ./network_spotcheck.sh [OPTIONS]
#
# Options:
#   --mode free       VT free tier: 4 lookups/min, 500/day, 15.5K/month (default)
#   --mode premium    VT premium: no throttle
#   --mode passive    Skip all API lookups, collect + reverse DNS only
#   --resume          Resume the most recent incomplete session
#   --resume <name>   Resume a specific named session
#   --session <name>  Tag this run with a name (default: timestamp)
#   --sessions        List all saved sessions and exit
#   --vt-only         Only run VirusTotal (skip AbuseIPDB)
#   --abuse-only      Only run AbuseIPDB (skip VirusTotal)
#   --quota           Show remaining VT quota and exit
#   --reset-quota     Reset the quota tracker and exit
#
# Environment:
#   ABUSEIPDB_API_KEY   free at https://www.abuseipdb.com
#   VIRUSTOTAL_API_KEY  free at https://www.virustotal.com
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
DIM='\033[2m'
BLD='\033[1m'
RST='\033[0m'

ABUSEIPDB_KEY="${ABUSEIPDB_API_KEY:-}"
VT_KEY="${VIRUSTOTAL_API_KEY:-}"
STANDARD_PORTS="443 80 53 8080 8443 5228 5223 993 587 465 143"
REPORT_FILE="/tmp/network_spotcheck_$(date +%Y%m%d_%H%M%S).txt"

# --- VT free tier limits ---
VT_FREE_RATE=4
VT_FREE_DELAY=15
VT_FREE_DAILY_MAX=500
VT_FREE_MONTHLY_MAX=15500
VT_QUOTA_FILE="$HOME/.vt_quota"

# --- Session state ---
SESSION_DIR="$HOME/.spotcheck_sessions"
SESSION_NAME=""
RESUME_SESSION=""
DO_RESUME=0

# --- Defaults ---
MODE="free"
SKIP_VT=0
SKIP_ABUSE=0

# =============================================================================
# Quota tracker
# =============================================================================

init_quota_file() {
  [[ ! -f "$VT_QUOTA_FILE" ]] && echo "0|0|$(date +%j)|$(date +%m)" > "$VT_QUOTA_FILE"
}

read_quota() {
  init_quota_file
  local data
  data=$(cat "$VT_QUOTA_FILE")
  QT_DAY_COUNT=$(echo "$data" | cut -d'|' -f1)
  QT_MONTH_COUNT=$(echo "$data" | cut -d'|' -f2)
  QT_LAST_DAY=$(echo "$data" | cut -d'|' -f3)
  QT_LAST_MONTH=$(echo "$data" | cut -d'|' -f4)
  local today_day today_month
  today_day=$(date +%j); today_month=$(date +%m)
  if [[ "$QT_LAST_MONTH" != "$today_month" ]]; then
    QT_MONTH_COUNT=0; QT_DAY_COUNT=0
    QT_LAST_MONTH="$today_month"; QT_LAST_DAY="$today_day"
  elif [[ "$QT_LAST_DAY" != "$today_day" ]]; then
    QT_DAY_COUNT=0; QT_LAST_DAY="$today_day"
  fi
}

write_quota() {
  echo "${QT_DAY_COUNT}|${QT_MONTH_COUNT}|${QT_LAST_DAY}|${QT_LAST_MONTH}" > "$VT_QUOTA_FILE"
}

increment_quota() {
  QT_DAY_COUNT=$((QT_DAY_COUNT + 1))
  QT_MONTH_COUNT=$((QT_MONTH_COUNT + 1))
  write_quota
}

quota_remaining_daily()  { echo $((VT_FREE_DAILY_MAX - QT_DAY_COUNT)); }
quota_remaining_monthly() { echo $((VT_FREE_MONTHLY_MAX - QT_MONTH_COUNT)); }

show_quota() {
  read_quota
  echo ""
  echo "  VirusTotal Free Tier Quota Tracker"
  echo "  -----------------------------------"
  echo "  Daily:   ${QT_DAY_COUNT} / ${VT_FREE_DAILY_MAX}  ($(quota_remaining_daily) remaining)"
  echo "  Monthly: ${QT_MONTH_COUNT} / ${VT_FREE_MONTHLY_MAX}  ($(quota_remaining_monthly) remaining)"
  echo "  Tracker: ${VT_QUOTA_FILE}"
  echo ""
}

can_query_vt_free() {
  [[ "$(quota_remaining_daily)" -gt 0 ]] && [[ "$(quota_remaining_monthly)" -gt 0 ]]
}

# =============================================================================
# Session management
# =============================================================================

ensure_session_dir() { mkdir -p "$SESSION_DIR"; }

# Session layout:
#   $SESSION_DIR/<name>/ips.txt        -- full IP list for this session (one per line)
#   $SESSION_DIR/<name>/connections.txt -- raw connection data
#   $SESSION_DIR/<name>/results.jsonl   -- one JSON line per checked IP
#   $SESSION_DIR/<name>/meta.txt       -- mode, timestamps, status

session_path() { echo "$SESSION_DIR/$1"; }

list_sessions() {
  ensure_session_dir
  echo ""
  echo "  Saved sessions:"
  echo "  ----------------"
  local found=0
  for meta in "$SESSION_DIR"/*/meta.txt; do
    [[ -f "$meta" ]] || continue
    found=1
    local sdir sname status total checked
    sdir=$(dirname "$meta")
    sname=$(basename "$sdir")
    status=$(grep '^status=' "$meta" | cut -d= -f2)
    total=$(wc -l < "$sdir/ips.txt" 2>/dev/null | tr -d ' ')
    checked=$(wc -l < "$sdir/results.jsonl" 2>/dev/null | tr -d ' ')
    local color="$GRN"
    [[ "$status" != "complete" ]] && color="$YLW"
    printf "  %-30s %b%-12s${RST}  %s/%s IPs checked\n" "$sname" "$color" "[$status]" "$checked" "$total"
  done
  if [[ "$found" -eq 0 ]]; then
    echo "  (none)"
  fi
  echo ""
}

find_latest_incomplete_session() {
  ensure_session_dir
  local latest=""
  for meta in "$SESSION_DIR"/*/meta.txt; do
    [[ -f "$meta" ]] || continue
    local status
    status=$(grep '^status=' "$meta" | cut -d= -f2)
    if [[ "$status" != "complete" ]]; then
      latest=$(basename "$(dirname "$meta")")
    fi
  done
  echo "$latest"
}

create_session() {
  local name="$1"
  local sdir
  sdir=$(session_path "$name")
  mkdir -p "$sdir"
  echo "$CONNECTIONS" > "$sdir/connections.txt"
  echo "$UNIQUE_IPS"  > "$sdir/ips.txt"
  cat > "$sdir/meta.txt" <<METAEOF
status=in_progress
mode=$MODE
created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
updated=$(date -u +%Y-%m-%dT%H:%M:%SZ)
METAEOF
  touch "$sdir/results.jsonl"
}

session_already_checked() {
  local sdir="$1" ip="$2"
  grep -q "\"ip\":\"${ip}\"" "$sdir/results.jsonl" 2>/dev/null
}

save_ip_result() {
  local sdir="$1" ip="$2" rdns="$3" procs="$4" abuse="$5" vt="$6" flag="$7"
  # Strip ANSI for storage
  abuse=$(echo -e "$abuse" | sed 's/\x1b\[[0-9;]*m//g')
  vt=$(echo -e "$vt" | sed 's/\x1b\[[0-9;]*m//g')
  flag=$(echo -e "$flag" | sed 's/\x1b\[[0-9;]*m//g')
  printf '{"ip":"%s","rdns":"%s","procs":"%s","abuse":"%s","vt":"%s","flag":"%s","ts":"%s"}\n' \
    "$ip" "$rdns" "$procs" "$abuse" "$vt" "$flag" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$sdir/results.jsonl"
  # Update timestamp
  sed -i '' "s/^updated=.*/updated=$(date -u +%Y-%m-%dT%H:%M:%SZ)/" "$sdir/meta.txt" 2>/dev/null || true
}

mark_session_complete() {
  local sdir="$1"
  sed -i '' 's/^status=.*/status=complete/' "$sdir/meta.txt" 2>/dev/null || true
  sed -i '' "s/^updated=.*/updated=$(date -u +%Y-%m-%dT%H:%M:%SZ)/" "$sdir/meta.txt" 2>/dev/null || true
}

mark_session_interrupted() {
  local sdir="$1"
  sed -i '' 's/^status=.*/status=interrupted/' "$sdir/meta.txt" 2>/dev/null || true
  sed -i '' "s/^updated=.*/updated=$(date -u +%Y-%m-%dT%H:%M:%SZ)/" "$sdir/meta.txt" 2>/dev/null || true
}

mark_session_quota_paused() {
  local sdir="$1"
  sed -i '' 's/^status=.*/status=quota_paused/' "$sdir/meta.txt" 2>/dev/null || true
  sed -i '' "s/^updated=.*/updated=$(date -u +%Y-%m-%dT%H:%M:%SZ)/" "$sdir/meta.txt" 2>/dev/null || true
}

print_session_results() {
  local sdir="$1"
  [[ ! -f "$sdir/results.jsonl" ]] && return
  echo ""
  printf "  ${BLD}%-18s %-42s %-14s %-20s %-18s${RST}\n" \
    "IP" "REVERSE DNS" "PROCS" "ABUSEIPDB" "VIRUSTOTAL" | tee -a "$REPORT_FILE"
  printf "  %-18s %-42s %-14s %-20s %-18s\n" \
    "--" "-----------" "-----" "---------" "----------" | tee -a "$REPORT_FILE"
  while IFS= read -r line; do
    local ip rdns procs abuse vt flag
    ip=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin)['ip'])" 2>/dev/null)
    rdns=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin)['rdns'])" 2>/dev/null)
    procs=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin)['procs'])" 2>/dev/null)
    abuse=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin)['abuse'])" 2>/dev/null)
    vt=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin)['vt'])" 2>/dev/null)
    flag=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin)['flag'])" 2>/dev/null)
    local flag_display=""
    [[ -n "$flag" ]] && flag_display="${RED}${flag}${RST}"
    printf "  %-18s %-42s %-14s %-20s %-18s %b\n" \
      "$ip" "$rdns" "$procs" "$abuse" "$vt" "$flag_display" | tee -a "$REPORT_FILE"
  done < "$sdir/results.jsonl"
}

# =============================================================================
# Parse arguments
# =============================================================================

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"; shift 2 ;;
    --resume)
      DO_RESUME=1
      if [[ $# -gt 1 ]] && [[ "$2" != --* ]]; then
        RESUME_SESSION="$2"; shift 2
      else
        shift
      fi
      ;;
    --session)
      SESSION_NAME="$2"; shift 2 ;;
    --sessions)
      list_sessions; exit 0 ;;
    --vt-only)
      SKIP_ABUSE=1; shift ;;
    --abuse-only)
      SKIP_VT=1; shift ;;
    --quota)
      read_quota; show_quota; exit 0 ;;
    --reset-quota)
      rm -f "$VT_QUOTA_FILE"; echo "  Quota tracker reset."; exit 0 ;;
    -h|--help)
      awk '/^# Usage:/{found=1} found && /^# ===/{exit} found{sub(/^# ?/,""); print}' "$0"
      exit 0 ;;
    *)
      echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ "$MODE" != "free" ]] && [[ "$MODE" != "premium" ]] && [[ "$MODE" != "passive" ]]; then
  echo "Invalid mode: $MODE (use: free, premium, passive)"; exit 1
fi

# =============================================================================
# Core functions
# =============================================================================

is_standard_port() {
  local port="$1"
  for p in $STANDARD_PORTS; do [[ "$port" == "$p" ]] && return 0; done
  return 1
}

reverse_dns() {
  local ip="$1" result
  result=$(dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//')
  [[ -z "$result" ]] && result="(no PTR)"
  echo "$result"
}

check_abuseipdb() {
  local ip="$1"
  if [[ -z "$ABUSEIPDB_KEY" ]] || [[ "$SKIP_ABUSE" -eq 1 ]]; then echo "skip"; return; fi
  local resp
  resp=$(curl -s --max-time 10 -G "https://api.abuseipdb.com/api/v2/check" \
    --data-urlencode "ipAddress=$ip" -d "maxAgeInDays=90" \
    -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" 2>/dev/null || echo "error")
  if [[ "$resp" == "error" ]] || [[ -z "$resp" ]]; then echo "error"; return; fi
  local score total_reports
  score=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('abuseConfidenceScore','?'))" 2>/dev/null || echo "?")
  total_reports=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('totalReports','?'))" 2>/dev/null || echo "?")
  echo "${score}%|${total_reports} reports"
}

check_virustotal() {
  local ip="$1"
  if [[ -z "$VT_KEY" ]] || [[ "$SKIP_VT" -eq 1 ]]; then echo "skip"; return; fi
  local resp
  resp=$(curl -s --max-time 10 "https://www.virustotal.com/api/v3/ip_addresses/$ip" \
    -H "x-apikey: $VT_KEY" 2>/dev/null || echo "error")
  if [[ "$resp" == "error" ]] || [[ -z "$resp" ]]; then echo "error"; return; fi
  local error_code
  error_code=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('code',''))" 2>/dev/null || echo "")
  if [[ "$error_code" == "QuotaExceededError" ]]; then echo "quota_hit"; return; fi
  local malicious suspicious harmless
  malicious=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('last_analysis_stats',{}).get('malicious',0))" 2>/dev/null || echo "?")
  suspicious=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('last_analysis_stats',{}).get('suspicious',0))" 2>/dev/null || echo "?")
  harmless=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('attributes',{}).get('last_analysis_stats',{}).get('harmless',0))" 2>/dev/null || echo "?")
  echo "${malicious}m/${suspicious}s/${harmless}h"
}

collect_connections() {
  lsof -i -P -n 2>/dev/null | grep ESTABLISHED | while read -r line; do
    local proc pid conn remote port
    proc=$(echo "$line" | awk '{print $1}')
    pid=$(echo "$line" | awk '{print $2}')
    conn=$(echo "$line" | awk '{print $9}')
    remote=$(echo "$conn" | sed 's/.*->//' | cut -d: -f1)
    port=$(echo "$conn" | sed 's/.*->//' | rev | cut -d: -f1 | rev)
    if [[ "$remote" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && \
       [[ "$remote" != 127.* ]] && [[ "$remote" != 192.168.* ]] && \
       [[ "$remote" != 10.* ]] && [[ "$remote" != 169.254.* ]]; then
      echo "${proc}|${pid}|${remote}|${port}"
    fi
  done | sort -u
}

# =============================================================================
# Ctrl+C trap -- save progress and exit cleanly
# =============================================================================

CURRENT_SESSION_DIR=""

cleanup_on_interrupt() {
  echo "" >&2
  echo -e "  ${YLW}Interrupted! Saving session state...${RST}" >&2
  if [[ -n "$CURRENT_SESSION_DIR" ]] && [[ -d "$CURRENT_SESSION_DIR" ]]; then
    mark_session_interrupted "$CURRENT_SESSION_DIR"
    local total checked
    total=$(wc -l < "$CURRENT_SESSION_DIR/ips.txt" | tr -d ' ')
    checked=$(wc -l < "$CURRENT_SESSION_DIR/results.jsonl" | tr -d ' ')
    echo -e "  ${GRN}Session saved:${RST} $checked/$total IPs checked" >&2
    echo -e "  Resume with: ${BLD}./network_spotcheck.sh --resume${RST}" >&2
  fi
  echo "" >&2
  exit 130
}

trap cleanup_on_interrupt INT TERM

# =============================================================================
# Resolve session: new run vs resume
# =============================================================================

ensure_session_dir

if [[ "$DO_RESUME" -eq 1 ]]; then
  # --- Resume mode ---
  if [[ -n "$RESUME_SESSION" ]]; then
    SDIR=$(session_path "$RESUME_SESSION")
    if [[ ! -d "$SDIR" ]]; then
      echo "  Session not found: $RESUME_SESSION"
      echo "  Run --sessions to list available sessions."
      exit 1
    fi
    SESSION_NAME="$RESUME_SESSION"
  else
    SESSION_NAME=$(find_latest_incomplete_session)
    if [[ -z "$SESSION_NAME" ]]; then
      echo "  No incomplete sessions to resume."
      echo "  Run --sessions to list available sessions."
      exit 0
    fi
    SDIR=$(session_path "$SESSION_NAME")
  fi

  CURRENT_SESSION_DIR="$SDIR"
  CONNECTIONS=$(cat "$SDIR/connections.txt")
  UNIQUE_IPS=$(cat "$SDIR/ips.txt")
  IP_COUNT=$(wc -l < "$SDIR/ips.txt" | tr -d ' ')
  ALREADY_CHECKED=$(wc -l < "$SDIR/results.jsonl" | tr -d ' ')
  REMAINING=$((IP_COUNT - ALREADY_CHECKED))

  # Reload mode from session
  MODE=$(grep '^mode=' "$SDIR/meta.txt" | cut -d= -f2)

  # Update status back to in_progress
  sed -i '' 's/^status=.*/status=in_progress/' "$SDIR/meta.txt" 2>/dev/null || true

  echo "" | tee "$REPORT_FILE"
  echo "=============================================="  | tee -a "$REPORT_FILE"
  echo "  RESUMING SESSION: $SESSION_NAME"              | tee -a "$REPORT_FILE"
  echo "  $(date)"                                      | tee -a "$REPORT_FILE"
  echo "=============================================="  | tee -a "$REPORT_FILE"
  echo ""                                               | tee -a "$REPORT_FILE"
  echo -e "  Mode: ${BLD}${MODE}${RST}"                | tee -a "$REPORT_FILE"
  echo -e "  Total IPs:     $IP_COUNT"                  | tee -a "$REPORT_FILE"
  echo -e "  Already done:  ${GRN}$ALREADY_CHECKED${RST}" | tee -a "$REPORT_FILE"
  echo -e "  Remaining:     ${YLW}$REMAINING${RST}"    | tee -a "$REPORT_FILE"

  if [[ "$MODE" == "free" ]]; then
    read_quota
    echo -e "  VT daily quota: ${CYN}$(quota_remaining_daily) of ${VT_FREE_DAILY_MAX} remaining${RST}" | tee -a "$REPORT_FILE"
    est_minutes=$(( (REMAINING * VT_FREE_DELAY + 59) / 60 ))
    echo -e "  ${DIM}Estimated time: ~${est_minutes} min for $REMAINING remaining IPs${RST}" | tee -a "$REPORT_FILE"
  fi
  echo "" | tee -a "$REPORT_FILE"

else
  # --- New run ---
  if [[ -z "$SESSION_NAME" ]]; then
    SESSION_NAME="scan_$(date +%Y%m%d_%H%M%S)"
  fi

  echo "" | tee "$REPORT_FILE"
  echo "=============================================="  | tee -a "$REPORT_FILE"
  echo "  NETWORK CONNECTION SPOT CHECK"               | tee -a "$REPORT_FILE"
  echo "  $(date)"                                      | tee -a "$REPORT_FILE"
  echo "=============================================="  | tee -a "$REPORT_FILE"
  echo ""                                               | tee -a "$REPORT_FILE"
  echo -e "  Mode:    ${BLD}${MODE}${RST}"             | tee -a "$REPORT_FILE"
  echo -e "  Session: ${BLD}${SESSION_NAME}${RST}"     | tee -a "$REPORT_FILE"

  case "$MODE" in
    free)
      read_quota
      echo -e "  VT rate:   ${CYN}${VT_FREE_RATE} req/min (${VT_FREE_DELAY}s delay)${RST}" | tee -a "$REPORT_FILE"
      echo -e "  VT daily:  ${CYN}$(quota_remaining_daily) of ${VT_FREE_DAILY_MAX} remaining${RST}" | tee -a "$REPORT_FILE"
      echo -e "  VT month:  ${CYN}$(quota_remaining_monthly) of ${VT_FREE_MONTHLY_MAX} remaining${RST}" | tee -a "$REPORT_FILE"
      ;;
    premium)
      echo -e "  VT rate:   ${GRN}unlimited (premium)${RST}" | tee -a "$REPORT_FILE" ;;
    passive)
      echo -e "  ${DIM}API lookups disabled${RST}" | tee -a "$REPORT_FILE" ;;
  esac

  if [[ -n "$ABUSEIPDB_KEY" ]] && [[ "$SKIP_ABUSE" -eq 0 ]]; then
    echo -e "  AbuseIPDB: ${GRN}enabled${RST}" | tee -a "$REPORT_FILE"
  else
    echo -e "  AbuseIPDB: ${DIM}disabled${RST}" | tee -a "$REPORT_FILE"
  fi
  if [[ -n "$VT_KEY" ]] && [[ "$SKIP_VT" -eq 0 ]] && [[ "$MODE" != "passive" ]]; then
    echo -e "  VT:        ${GRN}enabled${RST}" | tee -a "$REPORT_FILE"
  else
    echo -e "  VT:        ${DIM}disabled${RST}" | tee -a "$REPORT_FILE"
  fi
  echo "" | tee -a "$REPORT_FILE"

  # Collect
  echo -e "${BLD}[1/4] Collecting established connections...${RST}" | tee -a "$REPORT_FILE"
  echo "" | tee -a "$REPORT_FILE"

  CONNECTIONS=$(collect_connections)
  UNIQUE_IPS=$(echo "$CONNECTIONS" | cut -d'|' -f3 | sort -u)
  IP_COUNT=$(echo "$UNIQUE_IPS" | grep -c '.' || true)

  echo "  Found $(echo "$CONNECTIONS" | grep -c '.' || true) connections to $IP_COUNT unique remote IPs" | tee -a "$REPORT_FILE"

  # Create session
  SDIR=$(session_path "$SESSION_NAME")
  create_session "$SESSION_NAME"
  CURRENT_SESSION_DIR="$SDIR"

  ALREADY_CHECKED=0
  REMAINING="$IP_COUNT"

  if [[ "$MODE" == "free" ]] && [[ -n "$VT_KEY" ]] && [[ "$SKIP_VT" -eq 0 ]]; then
    read_quota
    local_remaining=$(quota_remaining_daily)
    if [[ "$IP_COUNT" -gt "$local_remaining" ]]; then
      echo "" | tee -a "$REPORT_FILE"
      echo -e "  ${YLW}$IP_COUNT IPs but only $local_remaining VT lookups left today.${RST}" | tee -a "$REPORT_FILE"
      echo -e "  ${YLW}Will pause when quota runs out. Resume tomorrow with --resume.${RST}" | tee -a "$REPORT_FILE"
    fi
    est_minutes=$(( (IP_COUNT * VT_FREE_DELAY + 59) / 60 ))
    echo -e "  ${DIM}Estimated time: ~${est_minutes} min for $IP_COUNT IPs${RST}" | tee -a "$REPORT_FILE"
  fi
  echo "" | tee -a "$REPORT_FILE"

  # Non-standard ports
  echo -e "${BLD}[2/4] Checking for non-standard ports...${RST}" | tee -a "$REPORT_FILE"
  echo "" | tee -a "$REPORT_FILE"
  nonstandard_found=0
  while IFS='|' read -r proc pid remote port; do
    if ! is_standard_port "$port"; then
      echo -e "  ${RED}UNUSUAL PORT${RST}  $proc (pid $pid) -> $remote:${RED}$port${RST}" | tee -a "$REPORT_FILE"
      nonstandard_found=1
    fi
  done <<< "$CONNECTIONS"
  [[ $nonstandard_found -eq 0 ]] && echo "  All connections use standard ports (443, 80, 53, etc.)" | tee -a "$REPORT_FILE"
  echo "" | tee -a "$REPORT_FILE"
fi

# =============================================================================
# [3/4] Per-IP analysis with session tracking
# =============================================================================

echo -e "${BLD}[3/4] Analyzing remote IPs (${REMAINING} remaining, ${ALREADY_CHECKED} already done)...${RST}" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

printf "  ${BLD}%-4s %-18s %-42s %-14s %-20s %-18s${RST}\n" \
  "#" "IP" "REVERSE DNS" "PROCS" "ABUSEIPDB" "VIRUSTOTAL" | tee -a "$REPORT_FILE"
printf "  %-4s %-18s %-42s %-14s %-20s %-18s\n" \
  "-" "--" "-----------" "-----" "---------" "----------" | tee -a "$REPORT_FILE"

vt_stopped=0
ip_idx=0
checked_this_run=0

while read -r ip; do
  [[ -z "$ip" ]] && continue
  ip_idx=$((ip_idx + 1))

  # Skip if already checked in this session
  if session_already_checked "$SDIR" "$ip"; then
    continue
  fi

  checked_this_run=$((checked_this_run + 1))

  procs=$(echo "$CONNECTIONS" | grep "|${ip}|" | cut -d'|' -f1 | sort -u | tr '\n' ',' | sed 's/,$//')
  rdns=$(reverse_dns "$ip")

  # --- AbuseIPDB ---
  abuse_result="--"
  if [[ "$MODE" != "passive" ]]; then
    abuse_result=$(check_abuseipdb "$ip")
    [[ "$abuse_result" == "skip" ]] && abuse_result="--"
  fi

  # --- VirusTotal ---
  vt_result="--"
  if [[ "$MODE" != "passive" ]] && [[ -n "$VT_KEY" ]] && [[ "$SKIP_VT" -eq 0 ]] && [[ "$vt_stopped" -eq 0 ]]; then
    case "$MODE" in
      free)
        if can_query_vt_free; then
          if [[ "$checked_this_run" -gt 1 ]]; then
            for ((countdown=VT_FREE_DELAY; countdown>0; countdown--)); do
              printf "\r  ${DIM}[%d/%d] rate limit: %ds ...${RST}  " "$ip_idx" "$IP_COUNT" "$countdown" >&2
              sleep 1
            done
            printf "\r%-60s\r" "" >&2
          fi
          vt_result=$(check_virustotal "$ip")
          if [[ "$vt_result" == "quota_hit" ]]; then
            vt_result="QUOTA_HIT"
            vt_stopped=1
            mark_session_quota_paused "$SDIR"
            echo -e "\n  ${RED}VT quota exhausted. Session paused.${RST}" | tee -a "$REPORT_FILE"
            echo -e "  ${CYN}Resume later with: ./network_spotcheck.sh --resume${RST}" | tee -a "$REPORT_FILE"
          else
            increment_quota
          fi
        else
          vt_result="quota_full"
          vt_stopped=1
          mark_session_quota_paused "$SDIR"
          echo -e "\n  ${YLW}VT daily quota reached. Session paused.${RST}" | tee -a "$REPORT_FILE"
          echo -e "  ${CYN}Resume tomorrow with: ./network_spotcheck.sh --resume${RST}" | tee -a "$REPORT_FILE"
        fi
        ;;
      premium)
        vt_result=$(check_virustotal "$ip")
        if [[ "$vt_result" == "quota_hit" ]]; then
          vt_result="QUOTA_HIT"
          vt_stopped=1
          echo -e "\n  ${RED}VT QuotaExceededError in premium mode. Check license.${RST}" | tee -a "$REPORT_FILE"
        fi
        ;;
    esac
  fi
  [[ "$vt_result" == "skip" ]] && vt_result="--"

  # --- Flag logic ---
  flag=""
  if [[ "$abuse_result" != "--" ]] && [[ "$abuse_result" != "error" ]]; then
    score_num=$(echo "$abuse_result" | cut -d'%' -f1)
    if [[ "$score_num" =~ ^[0-9]+$ ]] && [[ "$score_num" -gt 0 ]]; then
      flag="[FLAGGED]"
    fi
  fi
  vt_plain=$(echo -e "$vt_result" | sed 's/\x1b\[[0-9;]*m//g')
  if [[ "$vt_plain" =~ ^([0-9]+)m/ ]]; then
    mal_num="${BASH_REMATCH[1]}"
    [[ "$mal_num" -gt 0 ]] && flag="[FLAGGED]"
  fi

  # Save to session
  save_ip_result "$SDIR" "$ip" "$rdns" "$procs" "$abuse_result" "$vt_result" "$flag"

  # Print live
  local_flag_display=""
  [[ -n "$flag" ]] && local_flag_display="${RED}${flag}${RST}"
  vt_display="$vt_result"
  [[ "$vt_result" == "QUOTA_HIT" ]] && vt_display="${RED}QUOTA HIT${RST}"
  [[ "$vt_result" == "quota_full" ]] && vt_display="${YLW}quota full${RST}"
  printf "  %-4s %-18s %-42s %-14s %-20s %-18s %b\n" \
    "$ip_idx" "$ip" "$rdns" "$procs" "$abuse_result" "$vt_display" "$local_flag_display" | tee -a "$REPORT_FILE"

  # If quota paused, stop the loop
  [[ "$vt_stopped" -eq 1 ]] && [[ "$MODE" == "free" ]] && break

done <<< "$UNIQUE_IPS"

echo "" | tee -a "$REPORT_FILE"

# =============================================================================
# Session status
# =============================================================================

total_checked=$(wc -l < "$SDIR/results.jsonl" | tr -d ' ')

if [[ "$total_checked" -ge "$IP_COUNT" ]]; then
  mark_session_complete "$SDIR"
  echo -e "  ${GRN}Session complete: all $IP_COUNT IPs checked.${RST}" | tee -a "$REPORT_FILE"
else
  echo -e "  ${YLW}Session progress: $total_checked / $IP_COUNT IPs checked.${RST}" | tee -a "$REPORT_FILE"
  echo -e "  ${CYN}Resume: ./network_spotcheck.sh --resume${RST}" | tee -a "$REPORT_FILE"
fi

if [[ "$MODE" == "free" ]] && [[ -n "$VT_KEY" ]] && [[ "$SKIP_VT" -eq 0 ]]; then
  read_quota
  echo -e "  ${DIM}VT quota: day=$(quota_remaining_daily)/${VT_FREE_DAILY_MAX}  month=$(quota_remaining_monthly)/${VT_FREE_MONTHLY_MAX}${RST}" | tee -a "$REPORT_FILE"
fi
echo "" | tee -a "$REPORT_FILE"

# =============================================================================
# [4/4] Full merged results from session
# =============================================================================

echo -e "${BLD}[4/4] All results (merged across runs for this session)${RST}" | tee -a "$REPORT_FILE"
print_session_results "$SDIR"
echo "" | tee -a "$REPORT_FILE"

# Flagged summary
flagged_count=$(grep -c '"flag":"\[FLAGGED\]"' "$SDIR/results.jsonl" 2>/dev/null || true)
if [[ "$flagged_count" -gt 0 ]]; then
  echo -e "  ${RED}${BLD}$flagged_count IP(s) FLAGGED by threat intelligence:${RST}" | tee -a "$REPORT_FILE"
  grep '"flag":"\[FLAGGED\]"' "$SDIR/results.jsonl" | while IFS= read -r line; do
    local fip fvt fabuse
    fip=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin)['ip'])" 2>/dev/null)
    fvt=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin)['vt'])" 2>/dev/null)
    fabuse=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin)['abuse'])" 2>/dev/null)
    echo -e "    ${RED}$fip${RST}  abuse=$fabuse  vt=$fvt" | tee -a "$REPORT_FILE"
  done
  echo "" | tee -a "$REPORT_FILE"
else
  echo -e "  ${GRN}No IPs flagged by threat intelligence.${RST}" | tee -a "$REPORT_FILE"
  echo "" | tee -a "$REPORT_FILE"
fi

# =============================================================================
# Manual verification links
# =============================================================================

{
echo "=============================================="
echo "  MANUAL VERIFICATION LINKS"
echo "=============================================="
echo ""
echo "  AbuseIPDB:   https://www.abuseipdb.com/check/<IP>"
echo "  VirusTotal:  https://www.virustotal.com/gui/ip-address/<IP>"
echo "  Shodan:      https://www.shodan.io/host/<IP>"
echo "  GreyNoise:   https://viz.greynoise.io/ip/<IP>"
echo ""
} | tee -a "$REPORT_FILE"

echo -e "  Session: ${BLD}$SESSION_NAME${RST}  (${SESSION_DIR}/${SESSION_NAME}/)"
echo "  Report:  $REPORT_FILE"
echo ""
