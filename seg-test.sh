#!/usr/bin/env bash
# seg-test.sh — PCI segmentation reachability test, one-shot per source VLAN.
#
# Self-contained portable kit: the script, cde-all.txt, and clients/<name>.env all
# travel together, and results land in ./evidence/ right beside the script. Copy the
# kit folder (or ship a zip) per client — nothing is written outside it by default.
#
# Usage:
#   ./seg-test.sh --init <client>                                  # scaffold a new client (no sudo)
#   sudo ./seg-test.sh --client <name> <SOURCE_VLAN> [options]     # run a real scan (needs root)
#   ./seg-test.sh --client <name> <SOURCE_VLAN> --dry-run          # preview only, no packets, no root
#
# Options:
#   --check                 report which required tools are present/missing, then exit
#   --install-deps          install any missing tools via apt (Debian/Kali; needs root).
#                           Combine with --check, --init, or a real run.
#   --full-tcp              also run a rate-limited all-ports TCP scan (slow)
#   --skip-udp              skip the UDP selected-ports scan
#   --expect-cidr <cidr>    abort unless a local interface is inside <cidr>
#                           (guards against scanning from the wrong VLAN)
#   --force                 continue even if the --expect-cidr guard fails
#   --dry-run               show exactly what would run, send no packets, no root needed
#
# Prerequisites (Kali/Debian test VM):
#   Tools: nmap, nc (netcat), curl, traceroute, ip (iproute2), awk, sed, grep, tar,
#          sha256sum + tee/cut/paste/date (coreutils).
#   Install everything in one line:
#     sudo apt-get update && sudo apt-get install -y \
#       nmap netcat-traditional curl traceroute iproute2 gawk sed grep tar coreutils
#   Or let the script handle it:
#     bash seg-test.sh --check                       # report what's missing (no root)
#     sudo bash seg-test.sh --check --install-deps   # install the missing ones (apt)
#   Every real run also preflight-checks; add --install-deps to auto-fix gaps first.
#
# Examples:
#   ./seg-test.sh --check
#   ./seg-test.sh --init miskpay
#   sudo ./seg-test.sh --client miskpay VLAN_44
#   sudo ./seg-test.sh --client miskpay VLAN_44 --expect-cidr 10.20.44.0/24
#   sudo ./seg-test.sh --client trustbank VLAN_41_Compliance --full-tcp
#
# Per-client files (all beside the script, or under $ROOT if you override it):
#   clients/<name>.env   client config: CLIENT_NAME, optional ROOT / TRACE_ANCHOR /
#                        EXPECTED_SRC_CIDR / TCP_HOTSPOTS[] / HTTPS_HOTSPOTS[]
#   cde-all.txt          cardholder IPs, one per line (the CDE target list)
#   evidence/            results — one timestamped folder per VLAN run, plus a
#                        .tar.gz + .sha256 of each run for tamper-evident evidence
#
# What it does (per source VLAN, in order):
#   1. Sanity / prereq checks
#   2. Creates timestamped evidence folder under $ROOT/evidence/
#   3. Records baseline (date, source IP, route, traceroute to TRACE_ANCHOR)
#      + optional source-VLAN guard (--expect-cidr / EXPECTED_SRC_CIDR)
#   4. Host discovery against every CDE IP
#   5. TCP common-ports scan (~25 ports) against every CDE IP
#   6. TCP full-port scan (only if --full-tcp passed, rate-limited)
#   7. UDP selected-ports scan (unless --skip-udp passed)
#   8. Manual hot-spot checks (prior-report findings, defined per client)
#   9. Open-ports summary + tamper-evident archive (.tar.gz + .sha256)
#
# Does NOT:
#   - Make Pass/Fail decisions (that's a human task at report time)
#   - Capture pcap (run that interactively when an ambiguous result needs proof)
#   - Brute-force, exploit, or run nmap vuln scripts (out of scope per ROE)
#   - Touch any IP not in cde-all.txt / the client's hot-spot lists

set -u
set -o pipefail

# -------------------------------------------------------------------- config

# TCP common ports — every port flagged in prior reports, plus the usual suspects
TCP_COMMON_PORTS="21,22,23,25,53,80,110,135,139,143,389,443,445,1433,1521,3306,3389,5432,5900,5985,5986,6379,8080,8443,9200"

# UDP selected ports
UDP_PORTS="53,67,68,69,123,137,138,161,162,500,514,4500"

# Kit location. Everything lives beside the script unless a client env overrides ROOT.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${CLIENTS_DIR:=$SCRIPT_DIR/clients}"

# Required tools, as "command:apt-package". Command names differ from package names
# (nc -> netcat-traditional, ip -> iproute2, sha256sum -> coreutils), so map both.
REQUIRED_DEPS=(
  "nmap:nmap"
  "nc:netcat-traditional"
  "curl:curl"
  "traceroute:traceroute"
  "ip:iproute2"
  "awk:gawk"
  "sed:sed"
  "grep:grep"
  "tar:tar"
  "sha256sum:coreutils"
  "tee:coreutils"
  "cut:coreutils"
  "paste:coreutils"
  "date:coreutils"
)

# -------------------------------------------------------------------- helpers

usage() {
  # Print the top comment block (everything from line 2 up to the first non-# line).
  awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
}

# Populate MISSING_TOOLS / MISSING_PKGS (space-strings, to stay set -u safe on
# empty). Returns 0 if every required tool is present, 1 otherwise.
check_deps() {
  MISSING_TOOLS=""
  MISSING_PKGS=""
  local pair tool pkg
  for pair in "${REQUIRED_DEPS[@]}"; do
    tool="${pair%%:*}"; pkg="${pair#*:}"
    if ! command -v "$tool" >/dev/null 2>&1; then
      MISSING_TOOLS="$MISSING_TOOLS $tool"
      case " $MISSING_PKGS " in *" $pkg "*) : ;; *) MISSING_PKGS="$MISSING_PKGS $pkg" ;; esac
    fi
  done
  MISSING_TOOLS="${MISSING_TOOLS# }"
  MISSING_PKGS="${MISSING_PKGS# }"
  [[ -z "$MISSING_TOOLS" ]]
}

# Print a per-tool present/missing table + the exact install command. Returns 1 if
# anything is missing so callers can decide whether to stop.
report_deps() {
  echo "--- Dependency check ---"
  local pair tool
  for pair in "${REQUIRED_DEPS[@]}"; do
    tool="${pair%%:*}"
    if command -v "$tool" >/dev/null 2>&1; then
      printf '  [ok]      %s\n' "$tool"
    else
      printf '  [MISSING] %s\n' "$tool"
    fi
  done
  if check_deps; then
    echo "All required tools present."
    return 0
  fi
  echo
  echo "Missing: $MISSING_TOOLS"
  echo "Install (Kali/Debian):"
  echo "  sudo apt-get update && sudo apt-get install -y $MISSING_PKGS"
  echo "Or let this script do it:  sudo bash $0 --check --install-deps"
  return 1
}

# Install missing packages via apt (needs root + Debian/Kali). Returns non-zero if it
# can't (wrong OS / no root) or if tools are still missing afterwards.
install_deps() {
  check_deps && { echo "All required tools already present."; return 0; }
  echo "Missing: $MISSING_TOOLS"
  if [[ $EUID -ne 0 ]]; then
    echo "ERROR: --install-deps needs root (apt). Re-run with sudo." >&2
    return 1
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "ERROR: auto-install supports apt only (Debian/Kali)." >&2
    echo "       Install these manually: $MISSING_PKGS" >&2
    return 1
  fi
  echo ">>> apt-get install: $MISSING_PKGS"
  apt-get update && apt-get install -y $MISSING_PKGS || {
    echo "ERROR: apt install failed (offline VM? bad mirror?)." >&2; return 1; }
  if check_deps; then
    echo ">>> All dependencies now present."
    return 0
  fi
  echo "ERROR: still missing after install: $MISSING_TOOLS" >&2
  return 1
}

# Pure-bash IPv4-in-CIDR test. Returns 0 if $1 is inside CIDR $2, 1 otherwise.
ip_to_int() {
  local a b c d
  IFS=. read -r a b c d <<< "$1"
  # reject anything that isn't 4 numeric octets
  [[ "$a$b$c$d" =~ ^[0-9]+$ ]] || return 2
  echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}
ip_in_cidr() {
  local ip="$1" cidr="$2" net bits ipi neti mask
  [[ "$cidr" == */* ]] || return 2
  net="${cidr%/*}"; bits="${cidr#*/}"
  [[ "$bits" =~ ^[0-9]+$ ]] && (( bits >= 0 && bits <= 32 )) || return 2
  ipi=$(ip_to_int "$ip")  || return 2
  neti=$(ip_to_int "$net") || return 2
  if (( bits == 0 )); then mask=0; else mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF )); fi
  (( (ipi & mask) == (neti & mask) ))
}

# Scaffold a fresh client env + blank CDE list, then print next steps. No sudo.
write_client_template() {
  local client="$1" file="$2" today
  today="$(date +%F)"
  cat > "$file" <<EOF
# clients/${client}.env — ${client} PCI segmentation config.
# Created by: seg-test.sh --init ${client}  (${today})
# Sourced by: sudo ./seg-test.sh --client ${client} <SOURCE_VLAN>

# Display name used in headers/reports. Set to the real client name.
CLIENT_NAME="${client}"

# ROOT — where cde-all.txt and evidence/ live. Defaults to this kit's own folder
# (self-contained). Uncomment only if you want a separate per-engagement location.
# : "\${ROOT:=\$HOME/${client}-PCI-Segmentation}"

# TRACE_ANCHOR — one reachable CDE host for the baseline traceroute (optional).
# Pick any cardholder IP from cde-all.txt. Leave blank to skip the traceroute.
TRACE_ANCHOR=""

# EXPECTED_SRC_CIDR — optional default subnet guard. The source VLAN differs per run,
# so it is usually cleaner to pass --expect-cidr <cidr> on the command line instead.
# If set here (or via the flag), the run aborts unless a local interface is inside it —
# cheap insurance against scanning from the wrong VLAN and invalidating the result.
EXPECTED_SRC_CIDR=""

# Manual TCP hot-spots to re-test each round (from the client's PRIOR report).
#   First engagement  -> leave empty ().
#   Re-scan           -> add each prior finding so it is re-checked every round.
# Format per entry: "OUTFILE_BASE|LABEL|SPACE_SEP_HOSTS|SPACE_SEP_PORTS"
#   e.g. "core-db|Core banking Oracle+SSH|10.10.10.5|1521 22"
TCP_HOTSPOTS=()

# Manual HTTPS hot-spots (curl -vk https://host/).
# Format per entry: "OUTFILE_BASE|LABEL|SPACE_SEP_HOSTS"
#   e.g. "esxi|ESXi web UI|10.10.20.28 10.10.20.29"
HTTPS_HOTSPOTS=()
EOF
}

do_init() {
  local client="$1"
  if [[ "$client" =~ [[:space:]/] ]]; then
    echo "ERROR: --init client name must not contain spaces or slashes" >&2
    exit 1
  fi
  mkdir -p "$CLIENTS_DIR"
  local env_file="$CLIENTS_DIR/${client}.env"
  if [[ -e "$env_file" ]]; then
    echo "ERROR: $env_file already exists — refusing to overwrite." >&2
    echo "Edit it directly, or pick a different client name." >&2
    exit 1
  fi
  write_client_template "$client" "$env_file"

  # Blank CDE list beside the script, only if one isn't already here.
  local cde="$SCRIPT_DIR/cde-all.txt" cde_state="created"
  if [[ -e "$cde" ]]; then
    cde_state="already present (left untouched)"
  else
    cat > "$cde" <<'EOF'
# cde-all.txt — cardholder (CDE) IPs, ONE PER LINE. Lines starting with # are ignored.
# Fill this in for the current client, then run the scan per source VLAN.
# Example:
# 10.20.30.5
# 10.20.30.6
EOF
  fi

  cat <<EOF

============================================================
 Client '${client}' initialised.
============================================================
 Created : $env_file
 CDE list: $cde  (${cde_state})

 Next steps for THIS client:
   1. Put the cardholder IPs in:   cde-all.txt   (one per line)
   2. (optional) Edit $env_file:
        - TRACE_ANCHOR   -> a reachable CDE IP for the baseline traceroute
        - TCP_HOTSPOTS   -> prior-report findings to re-test (re-scans only)
   3. Get the SIGNED authorization / ROE for ${client} before sending any packet.
   4. Preview without scanning:
        ./seg-test.sh --client ${client} <SOURCE_VLAN> --dry-run
   5. Run for real from inside each source VLAN (needs root):
        sudo ./seg-test.sh --client ${client} <SOURCE_VLAN> --expect-cidr <that VLAN's CIDR>
   6. Repeat step 5 for every source VLAN. Evidence lands in ./evidence/.
============================================================
EOF
  echo
  if [[ ${INSTALL_DEPS:-0} -eq 1 ]]; then
    install_deps || true
  else
    report_deps || true
  fi
  exit 0
}

# -------------------------------------------------------------------- args

CLIENT=""
SOURCE_SEGMENT=""
INIT_CLIENT=""
CHECK_ONLY=0
INSTALL_DEPS=0
FULL_TCP=0
SKIP_UDP=0
DRY_RUN=0
FORCE=0
EXPECT_CIDR_FLAG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --init)         INIT_CLIENT="${2:-}"; shift 2 || { echo "ERROR: --init needs a client name" >&2; exit 1; } ;;
    --client)       CLIENT="${2:-}"; shift 2 || { echo "ERROR: --client needs a value" >&2; exit 1; } ;;
    --expect-cidr)  EXPECT_CIDR_FLAG="${2:-}"; shift 2 || { echo "ERROR: --expect-cidr needs a value" >&2; exit 1; } ;;
    --check)        CHECK_ONLY=1; shift ;;
    --install-deps) INSTALL_DEPS=1; shift ;;
    --full-tcp)     FULL_TCP=1; shift ;;
    --skip-udp)     SKIP_UDP=1; shift ;;
    --force)        FORCE=1; shift ;;
    --dry-run)      DRY_RUN=1; shift ;;
    -h|--help)      usage; exit 0 ;;
    -*)             echo "Unknown flag: $1" >&2; usage; exit 1 ;;
    *)              SOURCE_SEGMENT="$1"; shift ;;
  esac
done

# --check is a standalone diagnostic: report (or install) deps, then exit.
if [[ $CHECK_ONLY -eq 1 ]]; then
  if [[ $INSTALL_DEPS -eq 1 ]]; then install_deps; exit $?; fi
  report_deps; exit $?
fi

# --init short-circuits everything else (scaffold only, no sudo, no scan).
[[ -n "$INIT_CLIENT" ]] && do_init "$INIT_CLIENT"

[[ -z "$CLIENT" ]]         && { echo "ERROR: --client <name> required (or --init <name> to create one)" >&2; usage; exit 1; }
[[ -z "$SOURCE_SEGMENT" ]] && { echo "ERROR: source VLAN label required" >&2; usage; exit 1; }

# Reject spaces and slashes in the label — folder names depend on it
if [[ "$SOURCE_SEGMENT" =~ [[:space:]/] ]]; then
  echo "ERROR: SOURCE_SEGMENT must not contain spaces or slashes" >&2
  exit 1
fi
# Same for the client name — it selects a file path
if [[ "$CLIENT" =~ [[:space:]/] ]]; then
  echo "ERROR: --client must not contain spaces or slashes" >&2
  exit 1
fi

# -------------------------------------------------------------------- client config

CLIENT_ENV="$CLIENTS_DIR/${CLIENT}.env"
[[ -f "$CLIENT_ENV" ]] || {
  echo "ERROR: client config not found: $CLIENT_ENV" >&2
  echo "Create it with:  ./seg-test.sh --init $CLIENT" >&2
  echo "Available clients:" >&2
  ls -1 "$CLIENTS_DIR"/*.env 2>/dev/null | sed 's#.*/##; s#\.env$##' | grep -v '^_' | sed 's/^/  - /' >&2 || echo "  (none)" >&2
  exit 1
}
# shellcheck source=/dev/null
source "$CLIENT_ENV"

# Required from config
: "${CLIENT_NAME:?client config missing CLIENT_NAME}"
# ROOT defaults to the kit's own folder (self-contained); env may override.
: "${ROOT:=$SCRIPT_DIR}"
# Optional; empty means "skip the baseline traceroute"
: "${TRACE_ANCHOR:=}"
# Optional source-VLAN guard from env; --expect-cidr flag takes precedence.
: "${EXPECTED_SRC_CIDR:=}"
[[ -n "$EXPECT_CIDR_FLAG" ]] && EXPECTED_SRC_CIDR="$EXPECT_CIDR_FLAG"
# Hot-spot arrays are optional — default to empty if the config didn't set them
declare -p TCP_HOTSPOTS   >/dev/null 2>&1 || TCP_HOTSPOTS=()
declare -p HTTPS_HOTSPOTS >/dev/null 2>&1 || HTTPS_HOTSPOTS=()

# CDE target list — beside the script by default (env-overridable via CDE_LIST or ROOT)
: "${CDE_LIST:=$ROOT/cde-all.txt}"

# Validate --expect-cidr / EXPECTED_SRC_CIDR shape early (before any packets)
if [[ -n "$EXPECTED_SRC_CIDR" && ! "$EXPECTED_SRC_CIDR" == */* ]]; then
  echo "ERROR: --expect-cidr must be CIDR form, e.g. 10.20.44.0/24 (got '$EXPECTED_SRC_CIDR')" >&2
  exit 1
fi

# Soft target count for display (dry-run runs before the hard prereq checks).
# grep -c prints "0" and exits non-zero on no match, so neutralise the exit and
# default an empty result (missing file) to 0 — never chain a second `echo 0`.
CDE_COUNT=$(grep -cE '^[0-9]' "$CDE_LIST" 2>/dev/null || true); CDE_COUNT=${CDE_COUNT:-0}

# -------------------------------------------------------------------- dry-run preview

if [[ $DRY_RUN -eq 1 ]]; then
  echo "============================================================"
  echo " DRY RUN — $CLIENT_NAME / $SOURCE_SEGMENT   (no packets sent)"
  echo "============================================================"
  echo " Client cfg:   $CLIENT_ENV"
  echo " ROOT:         $ROOT"
  echo " CDE list:     $CDE_LIST  ($CDE_COUNT IP[s])"
  echo " Anchor:       ${TRACE_ANCHOR:-(none — baseline traceroute skipped)}"
  echo " Src guard:    ${EXPECTED_SRC_CIDR:-(none — manual 5s source-IP eyeball only)}"
  echo " Hot-spots:    ${#TCP_HOTSPOTS[@]} TCP group(s), ${#HTTPS_HOTSPOTS[@]} HTTPS group(s)"
  echo " Evidence ->   $ROOT/evidence/${SOURCE_SEGMENT}-<timestamp>/  (+ .tar.gz + .sha256)"
  echo
  echo " Would run against each CDE IP:"
  echo "   - host discovery : nmap -sn (with and without -Pn)"
  echo "   - TCP common     : -p $TCP_COMMON_PORTS"
  echo "   - TCP full       : $([[ $FULL_TCP -eq 1 ]] && echo 'yes  (-p-  --max-rate 500)' || echo 'no  (pass --full-tcp)')"
  echo "   - UDP            : $([[ $SKIP_UDP -eq 1 ]] && echo 'skipped (--skip-udp)' || echo "-p $UDP_PORTS")"
  echo
  echo " CDE targets:"
  grep -E '^[0-9]' "$CDE_LIST" 2>/dev/null | sed 's/^/     /' || echo "     (no list at $CDE_LIST)"
  echo "============================================================"
  echo " No evidence written. Remove --dry-run to execute for real (needs sudo)."
  exit 0
fi

# -------------------------------------------------------------------- prereqs

[[ $EUID -ne 0 ]] && { echo "ERROR: must run with sudo (nmap -sS / tcpdump need root)" >&2; exit 1; }

# Preflight tool check. With --install-deps, auto-fix via apt (we already have root).
if ! check_deps; then
  if [[ $INSTALL_DEPS -eq 1 ]]; then
    install_deps || exit 1
  else
    echo "ERROR: missing required tools: $MISSING_TOOLS" >&2
    echo "Fix: sudo apt-get install -y $MISSING_PKGS   (or add --install-deps to this run)" >&2
    exit 1
  fi
fi

[[ -f "$CDE_LIST" ]] || {
  echo "ERROR: CDE target list not found at $CDE_LIST" >&2
  echo "Populate it first ($CLIENT_NAME cardholder IPs, one per line)." >&2
  exit 1
}

CDE_COUNT=$(grep -cE '^[0-9]' "$CDE_LIST" || true)
[[ "$CDE_COUNT" -gt 0 ]] || { echo "ERROR: $CDE_LIST is empty" >&2; exit 1; }

# -------------------------------------------------------------------- setup

TS="$(date +%F-%H%M)"
OUTDIR="$ROOT/evidence/${SOURCE_SEGMENT}-${TS}"
mkdir -p "$OUTDIR"/{baseline,nmap,manual,pcap,screenshots}

LOG="$OUTDIR/run.log"
exec > >(tee -a "$LOG") 2>&1

echo "============================================================"
echo " $CLIENT_NAME Segmentation Test — source: $SOURCE_SEGMENT"
echo " Client cfg:   $CLIENT_ENV"
echo " Evidence dir: $OUTDIR"
echo " CDE targets:  $CDE_COUNT IPs"
echo " Src guard:    ${EXPECTED_SRC_CIDR:-(none — manual eyeball only)}"
echo " Hot-spots:    ${#TCP_HOTSPOTS[@]} TCP group(s), ${#HTTPS_HOTSPOTS[@]} HTTPS group(s)"
echo " Full TCP:     $([[ $FULL_TCP -eq 1 ]] && echo yes || echo no)"
echo " Skip UDP:     $([[ $SKIP_UDP -eq 1 ]] && echo yes || echo no)"
echo " Started:      $(date -Is)"
echo "============================================================"

# Record run metadata
cat > "$OUTDIR/baseline/run-metadata.txt" <<EOF
CLIENT_NAME: $CLIENT_NAME
CLIENT_ENV: $CLIENT_ENV
SOURCE_SEGMENT: $SOURCE_SEGMENT
TIMESTAMP_START: $(date -Is)
HOSTNAME: $(hostname)
USER: ${SUDO_USER:-$USER}
ARGS: $0 --client $CLIENT $SOURCE_SEGMENT $([[ $FULL_TCP -eq 1 ]] && echo --full-tcp) $([[ $SKIP_UDP -eq 1 ]] && echo --skip-udp) $([[ -n "$EXPECTED_SRC_CIDR" ]] && echo --expect-cidr "$EXPECTED_SRC_CIDR")
CDE_LIST: $CDE_LIST
CDE_COUNT: $CDE_COUNT
TRACE_ANCHOR: ${TRACE_ANCHOR:-(none)}
EXPECTED_SRC_CIDR: ${EXPECTED_SRC_CIDR:-(none)}
TCP_COMMON_PORTS: $TCP_COMMON_PORTS
UDP_PORTS: $UDP_PORTS
EOF

trap 'echo; echo "INTERRUPTED at $(date -Is). Partial evidence in $OUTDIR"; exit 130' INT TERM

# -------------------------------------------------------------------- 1. baseline

echo
echo "--- [1/6] Baseline ---"
date -Is                    | tee "$OUTDIR/baseline/start.txt"
ip addr                     | tee "$OUTDIR/baseline/ip-addr.txt"
ip route                    | tee "$OUTDIR/baseline/ip-route.txt"
ip neigh                    | tee "$OUTDIR/baseline/ip-neigh.txt" 2>/dev/null || true
if [[ -n "$TRACE_ANCHOR" ]]; then
  traceroute -n -w 2 -m 8 "$TRACE_ANCHOR" | tee "$OUTDIR/baseline/trace-to-cde-anchor.txt"
else
  echo "(no TRACE_ANCHOR set in $CLIENT_ENV — skipping baseline traceroute)" \
    | tee "$OUTDIR/baseline/trace-to-cde-anchor.txt"
fi

# Show the source IP loudly — you should glance at this to confirm you're in the
# VLAN you think you are. If wrong, Ctrl-C now and fix VPN before continuing.
SRC_IPS=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | paste -sd, -)
echo
echo ">>> Source IP(s): $SRC_IPS"

# Optional hard guard: abort if no local interface is inside the expected subnet.
if [[ -n "$EXPECTED_SRC_CIDR" ]]; then
  guard_ok=0
  for sip in ${SRC_IPS//,/ }; do
    if ip_in_cidr "$sip" "$EXPECTED_SRC_CIDR"; then guard_ok=1; break; fi
  done
  if [[ $guard_ok -eq 1 ]]; then
    echo ">>> Source-VLAN guard OK: a local interface is inside $EXPECTED_SRC_CIDR"
  else
    echo "!!! Source-VLAN guard FAILED: no interface in $EXPECTED_SRC_CIDR (have: ${SRC_IPS:-none})"
    if [[ $FORCE -eq 1 ]]; then
      echo "!!! --force given; continuing anyway (results may be from the WRONG VLAN)."
    else
      echo "!!! Aborting so you don't scan from the wrong VLAN. Fix the VLAN/VPN, or re-run with --force."
      date -Is | tee "$OUTDIR/baseline/end.txt"
      exit 3
    fi
  fi
else
  echo ">>> No --expect-cidr set. Confirm the above matches the expected VLAN. (5s pause)"
  sleep 5
fi

# -------------------------------------------------------------------- 2. host discovery

echo
echo "--- [2/6] Host discovery ---"
nmap -sn  -n -iL "$CDE_LIST" --reason -oA "$OUTDIR/nmap/01-host-discovery"
nmap -Pn -sn -n -iL "$CDE_LIST" --reason -oA "$OUTDIR/nmap/01-host-discovery-pn"

# -------------------------------------------------------------------- 3. TCP common

echo
echo "--- [3/6] TCP common-ports scan ---"
nmap -Pn -n -sS -iL "$CDE_LIST" \
  -p "$TCP_COMMON_PORTS" \
  --reason --open \
  -oA "$OUTDIR/nmap/02-tcp-common"

# -------------------------------------------------------------------- 4. TCP full (optional)

if [[ $FULL_TCP -eq 1 ]]; then
  echo
  echo "--- [4/6] TCP full-port scan (rate-limited) ---"
  nmap -Pn -n -sS -iL "$CDE_LIST" -p- --max-rate 500 --reason \
    -oA "$OUTDIR/nmap/03-tcp-full"
else
  echo
  echo "--- [4/6] TCP full-port scan SKIPPED (pass --full-tcp to enable) ---"
fi

# -------------------------------------------------------------------- 5. UDP (optional)

if [[ $SKIP_UDP -eq 0 ]]; then
  echo
  echo "--- [5/6] UDP selected-ports scan ---"
  nmap -Pn -n -sU -iL "$CDE_LIST" -p "$UDP_PORTS" --reason \
    -oA "$OUTDIR/nmap/04-udp-selected"
else
  echo
  echo "--- [5/6] UDP scan SKIPPED (--skip-udp) ---"
fi

# -------------------------------------------------------------------- 6. manual hot-spots

echo
echo "--- [6/6] Manual hot-spot checks (from $CLIENT_NAME prior findings) ---"

# TCP hot-spots. Each entry: "OUTFILE_BASE|LABEL|SPACE_SEP_HOSTS|SPACE_SEP_PORTS"
if [[ ${#TCP_HOTSPOTS[@]} -eq 0 ]]; then
  echo "  (no TCP hot-spots configured for $CLIENT_NAME — nothing carried over)"
else
  for entry in "${TCP_HOTSPOTS[@]}"; do
    IFS='|' read -r base label hosts ports <<< "$entry"
    echo
    echo "[hot-spot] $label"
    outfile="$OUTDIR/manual/${base}.txt"
    : > "$outfile"
    for ip in $hosts; do
      for p in $ports; do
        nc -vz -w 5 "$ip" "$p" 2>&1 | tee -a "$outfile" || true
      done
    done
  done
fi

# HTTPS hot-spots (curl -vk). Each entry: "OUTFILE_BASE|LABEL|SPACE_SEP_HOSTS"
if [[ ${#HTTPS_HOTSPOTS[@]} -eq 0 ]]; then
  echo "  (no HTTPS hot-spots configured for $CLIENT_NAME)"
else
  for entry in "${HTTPS_HOTSPOTS[@]}"; do
    IFS='|' read -r base label hosts <<< "$entry"
    echo
    echo "[hot-spot] $label"
    outfile="$OUTDIR/manual/${base}.txt"
    : > "$outfile"
    for ip in $hosts; do
      curl -vk --connect-timeout 5 "https://$ip/" >/dev/null 2>>"$outfile" || true
      echo "--- $ip ---" >> "$outfile"
    done
  done
fi

# -------------------------------------------------------------------- summary

echo
echo "--- Summary ---"
SUMMARY="$OUTDIR/manual/open-ports-summary.txt"
{
  echo "# Open ports reached from $SOURCE_SEGMENT ($CLIENT_NAME) at $(date -Is)"
  echo "# Source IPs: $SRC_IPS"
  echo
  grep -hE '/open/' "$OUTDIR"/nmap/*.gnmap 2>/dev/null || echo "(no /open/ entries found in nmap gnmap files)"
} | tee "$SUMMARY"

date -Is | tee "$OUTDIR/baseline/end.txt"

# -------------------------------------------------------------------- archive (tamper-evident)

echo
echo "--- Packaging evidence (tamper-evident) ---"
ARCHIVE_BASE="${CLIENT}-${SOURCE_SEGMENT}-${TS}"
FOLDER_NAME="$(basename "$OUTDIR")"
if ( cd "$ROOT/evidence" \
       && tar czf "${ARCHIVE_BASE}.tar.gz" "$FOLDER_NAME" \
       && sha256sum "${ARCHIVE_BASE}.tar.gz" > "${ARCHIVE_BASE}.tar.gz.sha256" ); then
  echo "Archive: $ROOT/evidence/${ARCHIVE_BASE}.tar.gz"
  echo "SHA-256: $(cut -d' ' -f1 "$ROOT/evidence/${ARCHIVE_BASE}.tar.gz.sha256")"
else
  echo "WARNING: evidence archiving failed — the raw folder is still at $OUTDIR"
fi

echo
echo "============================================================"
echo " DONE — $CLIENT_NAME / $SOURCE_SEGMENT"
echo " Evidence: $OUTDIR"
echo " Archive:  $ROOT/evidence/${ARCHIVE_BASE}.tar.gz (+ .sha256)"
echo " Quick look: cat $SUMMARY"
echo "============================================================"
