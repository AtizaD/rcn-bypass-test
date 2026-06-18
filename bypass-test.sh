#!/usr/bin/env bash
# ============================================================
#  Captive Portal Bypass Test Suite
#  Version: 2.6  |  Date: 2026-06-18
#
#  PURPOSE: Verify that captive portal bypass defenses are
#           working correctly on any MikroTik hotspot or WISP.
#           Compatible with RuralConnect, Zenfii, OpenWRT
#           Nodogsplash, MikroTik HotSpot, and others.
#
#  HOW TO USE:
#    1. Connect a device to the hotspot WiFi
#    2. Do NOT authenticate / enter a voucher code yet
#    3. Run:  bash bypass-test.sh
#    4. Review the PASS/FAIL summary at the end
#
#  OVERRIDE DEFAULTS (env vars):
#    PORTAL_DOMAIN=yourportal.com bash bypass-test.sh
#    PAYMENT_DOMAIN=api.stripe.com bash bypass-test.sh
#    ROUTER_IP=10.0.0.1 bash bypass-test.sh
#
#  PLATFORMS: Linux, Termux (Android), macOS
#  NOTE:      Some tests require root/sudo (iodine, hping3).
#             On Termux, run without sudo.
# ============================================================

# ── Colours ─────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[1;34m'; CYAN='\033[0;36m';  BOLD='\033[1m'; NC='\033[0m'

# ── Config ───────────────────────────────────────────────────
PORTAL_DOMAIN="${PORTAL_DOMAIN:-}"                    # auto-detected if not set via env
PAYMENT_DOMAIN="${PAYMENT_DOMAIN:-api.paystack.co}"   # payment gateway that must be pre-auth accessible
TELEMETRY_URL="${TELEMETRY_URL:-}"                     # optional: POST audit results here on failure
EXTERNAL_IP="8.8.8.8"                                 # IP that should be unreachable pre-auth
EXTERNAL_HOST="google.com"
DNS_TUNNEL_SANDBOX="sandbox.iodine.kryo.se"           # public iodine test server
ROUTER_IP="192.168.88.1"                              # hotspot gateway (auto-detected at runtime)
PORTAL_BASE_URL=""                                    # set in preflight() after gateway detection
PORTAL_CURL_RESOLVE=""                                # --resolve flags for .local mDNS domains
PORTAL_ON_CLOUDFLARE=0                                # set in preflight() — 1 if portal is CF-hosted
TIMEOUT=8                                              # seconds per test
IODINE_TIMEOUT=20                                      # iodine handshake timeout

# ── Result tracking ──────────────────────────────────────────
declare -a RESULTS=()
PASS=0; FAIL=0; WARN=0; SKIP=0

# ── Helpers ──────────────────────────────────────────────────
log()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
skip() { echo -e "${CYAN}[SKIP]${NC} $*"; }
sep()  { echo -e "${BOLD}────────────────────────────────────────────${NC}"; }
header() {
  echo ""
  sep
  echo -e "${BOLD}  $*${NC}"
  sep
}

record() {
  local status="$1" name="$2" detail="$3"
  RESULTS+=("${status}|${name}|${detail}")
  case "$status" in
    PASS) ((PASS++)) ;;
    FAIL) ((FAIL++)) ;;
    WARN) ((WARN++)) ;;
    SKIP) ((SKIP++)) ;;
  esac
}

# ── Platform detection ───────────────────────────────────────
detect_platform() {
  if [ -n "${PREFIX:-}" ] && echo "$PREFIX" | grep -q termux; then
    PLATFORM="termux"; PKG_MGR="pkg"; SUDO=""
  elif command -v apt-get &>/dev/null; then
    PLATFORM="debian"; PKG_MGR="apt-get"; SUDO="sudo"
  elif command -v dnf &>/dev/null; then
    PLATFORM="fedora"; PKG_MGR="dnf"; SUDO="sudo"
  elif command -v yum &>/dev/null; then
    PLATFORM="rhel"; PKG_MGR="yum"; SUDO="sudo"
  elif command -v brew &>/dev/null; then
    PLATFORM="macos"; PKG_MGR="brew"; SUDO=""
  else
    PLATFORM="unknown"; PKG_MGR=""; SUDO="sudo"
  fi
  log "Platform: ${PLATFORM} | Package manager: ${PKG_MGR:-none detected}"
}

# ── Portal auto-detection ─────────────────────────────────────
detect_portal_domain() {
  if [ -n "$PORTAL_DOMAIN" ]; then
    log "Portal domain (manual): ${PORTAL_DOMAIN}"
    return 0
  fi

  log "Auto-detecting captive portal domain..."

  # Strategy 1: follow HTTP redirect on standard captive-portal probe URLs.
  # When unauthenticated, the router redirects these to the portal login page.
  local probes=(
    "http://connectivitycheck.gstatic.com/generate_204"   # Android probe
    "http://captive.apple.com/hotspot-detect.html"         # iOS/macOS probe
    "http://neverssl.com/"                                  # always plain HTTP
    "http://example.com/"                                   # neutral fallback
  )

  local probe probe_host redirect_url final_url final_host
  for probe in "${probes[@]}"; do
    probe_host=$(echo "$probe" | sed 's|http://||' | cut -d'/' -f1)

    # Primary: read Location header WITHOUT following it — works for .local mDNS domains
    # that curl can't resolve via DNS (e.g. basscafe.local, portal.local)
    redirect_url=$(curl -s --max-time 8 --max-redirs 0 \
      -o /dev/null -w "%{redirect_url}" "$probe" 2>/dev/null)
    final_host=$(echo "$redirect_url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)

    # Fallback: follow redirects for multi-hop portals with resolvable domains
    if [ -z "$final_host" ] || [ "$final_host" = "$probe_host" ]; then
      final_url=$(curl -sk --max-time 8 -L --max-redirs 10 \
        -o /dev/null -w "%{url_effective}" "$probe" 2>/dev/null)
      final_host=$(echo "$final_url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
    fi

    # Accept if: final host differs from probe host AND is not a well-known non-portal host
    if [ -n "$final_host" ] && [ "$final_host" != "$probe_host" ] && \
       [[ "$final_host" != *"google"* ]] && [[ "$final_host" != *"apple"* ]] && \
       [[ "$final_host" != *"microsoft"* ]] && [[ "$final_host" != *"neverssl"* ]] && \
       [[ "$final_host" != *"example"* ]] && [[ "$final_host" != *"msft"* ]]; then
      PORTAL_DOMAIN="$final_host"
      ok "Portal auto-detected: ${BOLD}${PORTAL_DOMAIN}${NC}"
      log "  (redirect: ${probe} → ${redirect_url:-$final_url})"
      return 0
    fi
  done

  # Strategy 2: check if the gateway itself redirects to a portal domain
  if [ -n "$ROUTER_IP" ]; then
    local gw_redirect gw_url gw_host
    # Try Location header first (catches .local domains)
    gw_redirect=$(curl -s --max-time 5 --max-redirs 0 \
      -o /dev/null -w "%{redirect_url}" "http://${ROUTER_IP}/" 2>/dev/null)
    gw_host=$(echo "$gw_redirect" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
    # Fallback: follow redirects
    if [ -z "$gw_host" ] || [ "$gw_host" = "$ROUTER_IP" ]; then
      gw_url=$(curl -sk --max-time 5 -L --max-redirs 5 \
        -o /dev/null -w "%{url_effective}" "http://${ROUTER_IP}/" 2>/dev/null)
      gw_host=$(echo "$gw_url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
    fi
    if [ -n "$gw_host" ] && [ "$gw_host" != "$ROUTER_IP" ] && echo "$gw_host" | grep -q '\.'; then
      PORTAL_DOMAIN="$gw_host"
      ok "Portal detected via gateway redirect: ${BOLD}${PORTAL_DOMAIN}${NC}"
      return 0
    fi
  fi

  # Strategy 3: check DNS hijacking — if a blocked domain resolves to a non-standard IP,
  # that IP is likely the portal. Try a reverse lookup to get its hostname.
  if command -v dig &>/dev/null; then
    local hijacked_ip hijacked_host
    hijacked_ip=$(dig +short +time=4 "this-should-not-exist-$(date +%s).com" 2>/dev/null | head -1)
    if echo "$hijacked_ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
      hijacked_host=$(dig +short +time=4 -x "$hijacked_ip" 2>/dev/null | head -1 | sed 's/\.$//')
      if [ -n "$hijacked_host" ]; then
        PORTAL_DOMAIN="$hijacked_host"
        ok "Portal detected via DNS hijack hostname: ${BOLD}${PORTAL_DOMAIN}${NC}"
        return 0
      else
        PORTAL_DOMAIN="$hijacked_ip"
        ok "Portal detected via DNS hijack IP: ${BOLD}${PORTAL_DOMAIN}${NC}"
        return 0
      fi
    fi
  fi

  # Fallback: ask the operator
  echo ""
  warn "Could not auto-detect portal domain."
  echo -ne "  Enter portal domain [leave blank to skip portal tests]: "
  read -r _input
  PORTAL_DOMAIN="${_input:-}"
  if [ -n "$PORTAL_DOMAIN" ]; then
    log "Using portal domain: ${PORTAL_DOMAIN}"
  else
    warn "No portal domain set — portal integrity tests will be skipped."
  fi
}

is_root() { [ "$(id -u)" -eq 0 ]; }
can_sudo() { command -v sudo &>/dev/null && sudo -n true 2>/dev/null; }

# ── Platform command variants ─────────────────────────────────
# Called after install_tools so newly-installed binaries are visible.
setup_commands() {
  # python: 'python3' on most platforms, 'python' on Termux
  if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
  elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
  else
    PYTHON_CMD=""
  fi

  # hping: 'hping3' on Linux/Termux, 'hping' on macOS (brew install hping)
  if command -v hping3 &>/dev/null; then
    HPING_CMD="hping3"
  elif command -v hping &>/dev/null; then
    HPING_CMD="hping"
  else
    HPING_CMD=""
  fi

  # timeout: built-in on Linux; macOS needs 'gtimeout' from brew install coreutils
  if command -v timeout &>/dev/null; then
    TIMEOUT_CMD="timeout"
  elif command -v gtimeout &>/dev/null; then
    TIMEOUT_CMD="gtimeout"
  else
    TIMEOUT_CMD=""
  fi

  # ping -W: Linux/Termux interpret as seconds; macOS interprets as milliseconds
  # macOS uses -t for a seconds-based wait instead
  if [ "$PLATFORM" = "macos" ]; then
    PING_WAIT="-t"
  else
    PING_WAIT="-W"
  fi

  log "Tools: python=${PYTHON_CMD:-none} | hping=${HPING_CMD:-none} | timeout=${TIMEOUT_CMD:-none} | ping_wait=${PING_WAIT}"
}

# ── Tool installation ─────────────────────────────────────────
MISSING_TOOLS=()

check_tool() {
  local cmd="$1" pkg="$2"
  if ! command -v "$cmd" &>/dev/null; then
    warn "Missing: $cmd (package: $pkg)"
    MISSING_TOOLS+=("$pkg")
    return 1
  fi
  return 0
}

install_tools() {
  if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
    log "All tools already installed."
    return 0
  fi

  echo ""
  warn "Missing tools: ${MISSING_TOOLS[*]}"
  echo -n "Install them now? [Y/n] "
  read -r answer
  [[ "$answer" =~ ^[Nn] ]] && { warn "Skipping install — some tests will be skipped."; return 1; }

  case "$PLATFORM" in
    debian)
      # Debian/Ubuntu: package names match check_tool() calls directly
      $SUDO apt-get update -qq
      for pkg in "${MISSING_TOOLS[@]}"; do
        $SUDO apt-get install -y -qq "$pkg" && log "Installed: $pkg" || warn "Failed to install: $pkg"
      done
      ;;
    fedora|rhel)
      # Fedora/RHEL: several packages have different names from Debian
      for pkg in "${MISSING_TOOLS[@]}"; do
        local rpkg="$pkg"
        [[ "$pkg" == "iputils-ping"   ]] && rpkg="iputils"
        [[ "$pkg" == "dnsutils"       ]] && rpkg="bind-utils"
        [[ "$pkg" == "iproute2"       ]] && rpkg="iproute"
        [[ "$pkg" == "knot-dnsutils"  ]] && rpkg="knot-utils"
        [[ "$pkg" == "netcat-openbsd" ]] && rpkg="nmap-ncat"
        $SUDO "$PKG_MGR" install -y -q "$rpkg" && log "Installed: $rpkg" || warn "Failed to install: $rpkg"
      done
      ;;
    termux)
      # Termux: different names + some tools unavailable (no kernel access)
      pkg update -y -q 2>/dev/null
      for pkg in "${MISSING_TOOLS[@]}"; do
        local tpkg="$pkg"
        [[ "$pkg" == "iputils-ping"   ]] && tpkg="inetutils"
        [[ "$pkg" == "knot-dnsutils"  ]] && tpkg="knot-utils"
        [[ "$pkg" == "netcat-openbsd" ]] && tpkg="netcat"
        [[ "$pkg" == "python3"        ]] && tpkg="python"
        [[ "$pkg" == "hping3"         ]] && { warn "hping3 unavailable on Termux — TEST 9 will fall back to nmap"; continue; }
        [[ "$pkg" == "iodine"         ]] && { warn "iodine unavailable on Termux — TEST 6 will be skipped"; continue; }
        pkg install -y "$tpkg" 2>/dev/null && log "Installed: $tpkg" || warn "Not available in Termux: $tpkg"
      done
      ;;
    macos)
      # macOS: ping and nc are pre-installed; some tools have different Homebrew names
      for pkg in "${MISSING_TOOLS[@]}"; do
        local mpkg="$pkg"
        [[ "$pkg" == "iputils-ping"   ]] && { log "ping is pre-installed on macOS — skipping"; continue; }
        [[ "$pkg" == "netcat-openbsd" ]] && { log "nc is pre-installed on macOS — skipping"; continue; }
        [[ "$pkg" == "dnsutils"       ]] && mpkg="bind"
        [[ "$pkg" == "knot-dnsutils"  ]] && mpkg="knot-dns"
        [[ "$pkg" == "iproute2"       ]] && mpkg="iproute2mac"
        [[ "$pkg" == "hping3"         ]] && mpkg="hping"
        brew install "$mpkg" && log "Installed: $mpkg" || warn "Failed to install: $mpkg"
      done
      ;;
    *)
      warn "Unknown platform — please install manually: ${MISSING_TOOLS[*]}"
      ;;
  esac
}

# ── Pre-flight checks ─────────────────────────────────────────
preflight() {
  header "Pre-flight Checks"

  # Detect gateway IP using all available methods (order: Linux → Termux/Android → macOS → proc)
  local gw=""
  # Method 1: iproute2 (standard Linux)
  gw=$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')
  # Method 2: ip route get (works on Termux even without a default route entry)
  [ -z "$gw" ] && gw=$(ip route get 8.8.8.8 2>/dev/null | awk '/via/{for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}')
  # Method 3: macOS
  [ -z "$gw" ] && gw=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')
  # Method 4: Android system properties (Termux)
  if [ -z "$gw" ] && command -v getprop &>/dev/null; then
    for iface in wlan0 wlan1 eth0 rmnet0; do
      gw=$(getprop "dhcp.${iface}.gateway" 2>/dev/null)
      [ -n "$gw" ] && break
    done
  fi
  # Method 5: parse /proc/net/route (hex gateway, little-endian)
  if [ -z "$gw" ] && [ -f /proc/net/route ]; then
    local hex
    hex=$(awk 'NR>1 && $2=="00000000" && $3!="00000000" {print $3; exit}' /proc/net/route 2>/dev/null)
    if [ -n "$hex" ]; then
      gw=$(printf "%d.%d.%d.%d" \
        "0x${hex:6:2}" "0x${hex:4:2}" "0x${hex:2:2}" "0x${hex:0:2}" 2>/dev/null)
    fi
  fi

  if [ -n "$gw" ]; then
    ROUTER_IP="$gw"
    log "Gateway detected: $ROUTER_IP"
  else
    # Last resort: check if curl can reach anything at all
    if ! curl -s --max-time 4 --head "http://${ROUTER_IP}/" &>/dev/null; then
      fail "No network interface found. Are you connected to WiFi?"
      exit 1
    fi
    warn "Could not auto-detect gateway, using default: $ROUTER_IP"
  fi

  # Set portal URL scheme and resolve options.
  # .local mDNS domains have no SSL cert and can't be resolved via DNS —
  # use http:// and tell curl to connect via the router IP directly.
  if [[ "$PORTAL_DOMAIN" == *".local" ]]; then
    PORTAL_BASE_URL="http://${PORTAL_DOMAIN}"
    PORTAL_CURL_RESOLVE="--resolve ${PORTAL_DOMAIN}:80:${ROUTER_IP} --resolve ${PORTAL_DOMAIN}:443:${ROUTER_IP} --resolve www.${PORTAL_DOMAIN}:80:${ROUTER_IP} --resolve www.${PORTAL_DOMAIN}:443:${ROUTER_IP}"
  else
    PORTAL_BASE_URL="https://${PORTAL_DOMAIN}"
    PORTAL_CURL_RESOLVE=""
  fi

  # Detect if portal is hosted on Cloudflare (check for cf-ray or server: cloudflare headers)
  if [ -n "$PORTAL_DOMAIN" ] && [[ "$PORTAL_DOMAIN" != *".local" ]]; then
    local cf_headers
    # shellcheck disable=SC2086
    cf_headers=$(curl -s --max-time 6 $PORTAL_CURL_RESOLVE -I "${PORTAL_BASE_URL}" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    if echo "$cf_headers" | grep -q "cf-ray:\|server: cloudflare"; then
      PORTAL_ON_CLOUDFLARE=1
      log "Portal is Cloudflare-hosted — CF walled garden tests will run."
    else
      PORTAL_ON_CLOUDFLARE=0
      log "Portal is NOT on Cloudflare — CF-specific tests will be skipped."
    fi
  else
    PORTAL_ON_CLOUDFLARE=0
    log "Portal is NOT on Cloudflare (.local domain) — CF-specific tests will be skipped."
  fi

  # Verify we are NOT already authenticated (internet should be blocked)
  log "Checking that internet is blocked (pre-auth state)..."
  if curl -s --max-time 5 --head "https://${EXTERNAL_IP}" &>/dev/null; then
    echo ""
    warn "⚠️  Internet appears to be accessible already."
    warn "   This could mean:"
    warn "   (a) You are already authenticated on the hotspot, OR"
    warn "   (b) A bypass is already working!"
    warn "   Tests will run but results may be misleading."
    echo -n "   Continue anyway? [y/N] "
    read -r ans
    [[ ! "$ans" =~ ^[Yy] ]] && exit 0
  else
    ok "Internet is blocked — confirmed pre-auth state."
    record PASS "Pre-auth state" "Internet correctly blocked before auth"
  fi

  # Check if portal is reachable (walled garden sanity)
  log "Checking portal is reachable..."
  # shellcheck disable=SC2086
  if curl -s --max-time 8 $PORTAL_CURL_RESOLVE --head "${PORTAL_BASE_URL}" &>/dev/null; then
    ok "Portal domain reachable: ${PORTAL_DOMAIN}"
    record PASS "Portal reachable" "${PORTAL_DOMAIN} accessible in walled garden"
  else
    fail "Portal domain NOT reachable. Walled garden may be broken."
    record FAIL "Portal reachable" "${PORTAL_DOMAIN} not accessible — hotspot may be misconfigured"
  fi
}

# ── TEST 1: IPv6 Bypass ───────────────────────────────────────
test_ipv6() {
  header "TEST 1 — IPv6 Bypass"
  log "Checking if IPv6 is disabled on the router..."

  # Check if we got an IPv6 address (other than link-local fe80::)
  # macOS: 'ip -6' not available — use ifconfig instead
  local ipv6_global
  if [ "$PLATFORM" = "macos" ]; then
    ipv6_global=$(ifconfig 2>/dev/null | grep "inet6" | grep -v " fe80" | grep -v " ::1" | head -1)
  else
    ipv6_global=$(ip -6 addr show 2>/dev/null | grep "inet6" | grep -v " fe80" | grep -v " ::1" | head -1)
  fi

  if [ -n "$ipv6_global" ]; then
    fail "Device has a global IPv6 address: $ipv6_global"
    fail "IPv6 is NOT disabled — bypass possible via SLAAC"
    record FAIL "IPv6 disabled" "Device received global IPv6 address: $ipv6_global"
  else
    ok "No global IPv6 address — IPv6 is disabled or not routed."
    record PASS "IPv6 disabled" "No global IPv6 address assigned"
  fi

  # Also try reaching an IPv6-only host
  if command -v curl &>/dev/null; then
    if curl -6 -s --max-time "$TIMEOUT" --head "https://ipv6.google.com" &>/dev/null; then
      fail "IPv6 internet IS reachable — hotspot bypass via IPv6 confirmed!"
      record FAIL "IPv6 internet blocked" "curl -6 reached ipv6.google.com"
    else
      ok "IPv6 internet unreachable."
      record PASS "IPv6 internet blocked" "curl -6 ipv6.google.com timed out"
    fi
  fi
}

# ── TEST 2: ICMP Tunneling ────────────────────────────────────
test_icmp() {
  header "TEST 2 — ICMP Tunneling (ptunnel / icmptunnel)"

  # Test 2a: Small ping — must work (walled garden / router reachable)
  log "Testing small ICMP (≤64 bytes) — should succeed to router..."
  if ping -c 2 $PING_WAIT 3 "$ROUTER_IP" &>/dev/null 2>&1; then
    ok "Small ICMP to router works (expected)."
    record PASS "ICMP small (≤64B)" "ping to $ROUTER_IP succeeded"
  else
    if [ "$PLATFORM" = "termux" ]; then
      log "Small ICMP to router failed — expected on Android (raw ICMP needs root)."
      record SKIP "ICMP small (≤64B)" "Android blocks raw ICMP from non-root apps — not a firewall finding"
    else
      warn "Small ICMP to router failed — may be a firewall issue unrelated to tunneling."
      record WARN "ICMP small (≤64B)" "ping to $ROUTER_IP failed — check if ICMP is globally blocked"
    fi
  fi

  # Test 2b: Large ping to external — must be DROPPED (tunnel prevention)
  log "Testing oversized ICMP (500 bytes) to internet — should be DROPPED..."
  local large_result=0

  if is_root || can_sudo; then
    # Linux: -s sets data size (500 bytes data + 28 header = 528 bytes total)
    if ${SUDO} ping -c 2 $PING_WAIT "$TIMEOUT" -s 500 "$EXTERNAL_IP" &>/dev/null 2>&1; then
      large_result=1
    fi
  else
    # Try without sudo (works on most modern Linux and macOS)
    if ping -c 2 $PING_WAIT "$TIMEOUT" -s 500 "$EXTERNAL_IP" &>/dev/null 2>&1; then
      large_result=1
    fi
  fi

  if [ $large_result -eq 1 ]; then
    fail "Oversized ICMP (500B) reached internet — ICMP tunnel blocking NOT working!"
    record FAIL "ICMP tunnel block" "ping -s 500 $EXTERNAL_IP succeeded — ptunnel bypass possible"
  else
    ok "Oversized ICMP dropped — ICMP tunneling blocked."
    record PASS "ICMP tunnel block" "ping -s 500 $EXTERNAL_IP timed out/dropped"
  fi

  # Test 2c: Medium ping (150 bytes) — below our 200 threshold, should work
  log "Testing medium ICMP (150 bytes) — should succeed (below 200-byte block threshold)..."
  if ping -c 2 $PING_WAIT 5 -s 150 "$ROUTER_IP" &>/dev/null 2>&1; then
    ok "Medium ICMP (150B) to router works — threshold is correct."
    record PASS "ICMP threshold (150B)" "ping -s 150 passes as expected"
  else
    if [ "$PLATFORM" = "termux" ]; then
      log "Medium ICMP (150B) failed — expected on Android (raw ICMP needs root)."
      record SKIP "ICMP threshold (150B)" "Android blocks raw ICMP from non-root apps — not a firewall finding"
    else
      warn "Medium ICMP (150B) failed — threshold may be too aggressive."
      record WARN "ICMP threshold (150B)" "ping -s 150 failed — may cause diagnostic issues"
    fi
  fi
}

# ── TEST 3: DNS-over-TLS (DoT) ────────────────────────────────
test_dot() {
  header "TEST 3 — DNS-over-TLS (port 853)"

  if ! command -v kdig &>/dev/null; then
    skip "kdig not installed — skipping DoT test."
    record SKIP "DoT blocked (853)" "kdig not available"
    return
  fi

  log "Testing DNS-over-TLS to 1.1.1.1:853 — should be BLOCKED..."
  if kdig @1.1.1.1 +tls "$EXTERNAL_HOST" &>/dev/null 2>&1; then
    fail "DoT query succeeded — port 853 is NOT blocked!"
    record FAIL "DoT blocked (853)" "kdig @1.1.1.1 +tls succeeded — DNS-over-TLS bypass possible"
  else
    ok "DoT query failed — port 853 is blocked."
    record PASS "DoT blocked (853)" "kdig @1.1.1.1 +tls timed out/refused"
  fi
}

# ── TEST 4: QUIC / HTTP3 (UDP 443) ───────────────────────────
test_quic() {
  header "TEST 4 — QUIC / HTTP3 (UDP port 443)"

  # Method A: curl --http3 if supported
  if curl --version 2>/dev/null | grep -q "HTTP3\|http3\|quic"; then
    log "curl has HTTP/3 support — testing QUIC directly..."
    if curl --http3-prior-knowledge -s --max-time "$TIMEOUT" "https://cloudflare.com" &>/dev/null; then
      fail "HTTP/3 over QUIC succeeded — UDP 443 is NOT blocked!"
      record FAIL "QUIC blocked (UDP 443)" "curl --http3 cloudflare.com succeeded"
    else
      ok "HTTP/3 failed — QUIC is blocked."
      record PASS "QUIC blocked (UDP 443)" "curl --http3 cloudflare.com failed"
    fi
    return
  fi

  # Method B: Python UDP test (checks if UDP 443 packets get out)
  if [ -n "$PYTHON_CMD" ]; then
    log "Testing QUIC via Python UDP probe (UDP 443 to $EXTERNAL_IP)..."
    local py_result
    py_result=$($PYTHON_CMD -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
try:
    s.connect(('$EXTERNAL_IP', 443))
    # Send a QUIC-like initial packet (just 1200 bytes to trigger response or ICMP unreach)
    s.send(b'\\xc0' + b'\\x00' * 1199)
    data = s.recv(1024)
    print('REACHABLE')
except socket.timeout:
    print('TIMEOUT')
except Exception as e:
    print('BLOCKED:' + str(e))
finally:
    s.close()
" 2>/dev/null)
    if echo "$py_result" | grep -q "REACHABLE"; then
      fail "UDP 443 probe got a response — QUIC may not be blocked!"
      record FAIL "QUIC blocked (UDP 443)" "UDP probe to $EXTERNAL_IP:443 got response"
    else
      ok "UDP 443 probe timed out — QUIC appears blocked."
      record PASS "QUIC blocked (UDP 443)" "UDP probe to $EXTERNAL_IP:443: $py_result"
    fi
    return
  fi

  # Method C: nc (netcat) UDP probe
  if command -v nc &>/dev/null; then
    log "Testing UDP 443 via netcat..."
    if echo "test" | nc -u -w "$TIMEOUT" "$EXTERNAL_IP" 443 &>/dev/null; then
      warn "nc UDP 443 completed — inconclusive (UDP has no connection state)."
      record WARN "QUIC blocked (UDP 443)" "nc UDP test inconclusive — install python3 for better test"
    fi
    return
  fi

  skip "No HTTP/3-capable curl, python, or nc available — skipping QUIC test."
  record SKIP "QUIC blocked (UDP 443)" "No suitable tool available"
}

# ── TEST 5: DNS Redirect ──────────────────────────────────────
test_dns_redirect() {
  header "TEST 5 — DNS Redirect (all DNS → router resolver)"

  if ! command -v dig &>/dev/null; then
    skip "dig not installed — skipping DNS redirect test."
    record SKIP "DNS redirect" "dig not available"
    return
  fi

  # Test 5a: Normal DNS resolution should work (via redirect to router)
  log "Testing normal DNS resolution (should work via router resolver)..."
  if dig +short +time=5 "$EXTERNAL_HOST" &>/dev/null 2>&1; then
    ok "DNS resolution works (router resolver is forwarding correctly)."
    record PASS "DNS resolution works" "dig $EXTERNAL_HOST succeeded via router"
  else
    fail "DNS resolution broken — the redirect may have broken DNS entirely."
    record FAIL "DNS resolution works" "dig $EXTERNAL_HOST failed — check /ip dns allow-remote-requests"
  fi

  # Test 5b: Direct query to external resolver should be intercepted (redirected)
  # With redirect: query to 8.8.8.8:53 is rewritten to router:53, which still resolves
  # Without redirect: query goes directly to 8.8.8.8
  # We detect redirect by checking if querying a non-existent resolver still works
  log "Testing DNS redirect (querying a non-existent/blocked resolver)..."
  # Use an IP that is NOT a real resolver — if DNS redirect is on, the router handles it anyway
  local fake_resolver="192.0.2.1"  # TEST-NET-1, should not be a real resolver
  if dig +short +time=5 @"$fake_resolver" "$EXTERNAL_HOST" &>/dev/null 2>&1; then
    ok "DNS redirect confirmed — query to $fake_resolver was intercepted and resolved by router."
    record PASS "DNS redirect active" "Query to fake resolver $fake_resolver still resolved via router"
  else
    warn "Could not confirm DNS redirect — query to $fake_resolver failed."
    warn "This is expected if the router drops unreachable targets before NAT redirect."
    record WARN "DNS redirect active" "Redirect test inconclusive (fake resolver $fake_resolver unreachable)"
  fi

  # Test 5c: Verify DNS rate isn't completely broken (DNS tunnel rate limit side effect)
  log "Testing rapid DNS queries (should not be overly rate-limited)..."
  local ok_count=0
  for _ in 1 2 3 4 5; do
    dig +short +time=3 "$EXTERNAL_HOST" &>/dev/null && ((ok_count++)) || true
  done
  if [ "$ok_count" -ge 4 ]; then
    ok "DNS responds reliably ($ok_count/5 queries succeeded)."
    record PASS "DNS reliability" "$ok_count/5 rapid queries succeeded"
  elif [ "$ok_count" -ge 2 ]; then
    warn "DNS partially unreliable ($ok_count/5) — may indicate aggressive rate limiting."
    record WARN "DNS reliability" "$ok_count/5 rapid queries succeeded — check rate limit rules"
  else
    fail "DNS mostly failing ($ok_count/5) — redirect rule may be misconfigured."
    record FAIL "DNS reliability" "Only $ok_count/5 queries succeeded"
  fi
}

# ── TEST 6: DNS Tunneling (iodine) ────────────────────────────
test_dns_tunnel() {
  header "TEST 6 — DNS Tunneling (iodine)"

  if ! command -v iodine &>/dev/null; then
    skip "iodine not installed — skipping DNS tunnel test."
    record SKIP "DNS tunnel (iodine)" "iodine not available"
    return
  fi

  if ! is_root && ! can_sudo; then
    warn "iodine requires root/sudo — skipping."
    record SKIP "DNS tunnel (iodine)" "Root required but not available"
    return
  fi

  log "Attempting iodine DNS tunnel to ${DNS_TUNNEL_SANDBOX}..."
  log "(Timeout: ${IODINE_TIMEOUT}s — a tunnel attempt, not a connection)"

  # Run iodine in background, kill after timeout
  local iodine_log
  iodine_log=$(mktemp /tmp/iodine_test.XXXXXX)

  ${SUDO} ${TIMEOUT_CMD:-timeout} "$IODINE_TIMEOUT" iodine -f -r -P autodie \
    "$DNS_TUNNEL_SANDBOX" > "$iodine_log" 2>&1 &
  local iodine_pid=$!

  # Wait and read progress
  sleep "$IODINE_TIMEOUT"
  ${SUDO} kill "$iodine_pid" 2>/dev/null || true
  wait "$iodine_pid" 2>/dev/null || true

  local iodine_output
  iodine_output=$(cat "$iodine_log" 2>/dev/null)
  rm -f "$iodine_log"

  # Check if tunnel was established
  if echo "$iodine_output" | grep -qi "tunnel.*established\|Sending.*data\|connection.*established"; then
    fail "iodine DNS tunnel ESTABLISHED — DNS tunneling is NOT blocked!"
    fail "Output: $(echo "$iodine_output" | tail -3)"
    record FAIL "DNS tunnel (iodine)" "iodine established tunnel via ${DNS_TUNNEL_SANDBOX}"
  elif echo "$iodine_output" | grep -qi "bad password\|auth.*failed\|wrong.*version"; then
    warn "iodine connected to sandbox but auth failed — tunnel protocol reached NS."
    warn "DNS tunneling PARTIALLY working (data can flow, just wrong password)."
    record WARN "DNS tunnel (iodine)" "Reached sandbox NS server — redirect slows but doesn't fully block"
  elif echo "$iodine_output" | grep -qi "no.*reply\|timeout\|no route\|failed.*connect"; then
    ok "iodine failed to connect — DNS tunnel blocked."
    record PASS "DNS tunnel (iodine)" "iodine timed out — tunnel not established"
  else
    warn "iodine result inconclusive."
    warn "Output: $(echo "$iodine_output" | head -5)"
    record WARN "DNS tunnel (iodine)" "Inconclusive result — check manually"
  fi

  # Cleanup: remove tun device if iodine created one (ip on Linux, ifconfig on macOS)
  if [ "$PLATFORM" = "macos" ]; then
    ${SUDO} ifconfig dns0 down 2>/dev/null || true
  else
    ${SUDO} ip link delete dns0 2>/dev/null || true
  fi
}

# ── TEST 7: Walled Garden Scope ───────────────────────────────
test_cf_walled_garden() {
  if [ "$PORTAL_ON_CLOUDFLARE" -eq 1 ]; then
    header "TEST 7 — Cloudflare Walled Garden Scope"
    log "Portal is Cloudflare-hosted — running CF-specific walled garden checks."

    # CF Pages/Workers could be used as a WebSocket proxy by an attacker
    local cf_test_domain="cloudflare-eth.com"
    log "Testing that a random Cloudflare-hosted site is NOT freely accessible..."
    if curl -s --max-time "$TIMEOUT" --head "https://${cf_test_domain}" &>/dev/null; then
      warn "Cloudflare-hosted site ${cf_test_domain} is accessible (TCP 443)."
      warn "This is EXPECTED — only non-HTTP protocols on CF IPs can be blocked."
      warn "A determined attacker could still use WebSocket over HTTPS as a tunnel."
      warn "This is a known limitation of Cloudflare-based portal architecture."
      record WARN "CF walled garden scope" "${cf_test_domain} accessible via TCP 443 — WebSocket bypass theoretically possible"
    else
      ok "${cf_test_domain} not accessible — walled garden is very tight."
      record PASS "CF walled garden scope" "${cf_test_domain} not reachable pre-auth"
    fi

    # Non-standard ports to CF IPs should be blocked
    if command -v nc &>/dev/null; then
      log "Testing that non-standard ports to Cloudflare IPs are blocked..."
      local cf_ip="104.16.1.1"
      if nc -z -w 5 "$cf_ip" 8080 &>/dev/null 2>&1; then
        fail "Port 8080 to Cloudflare IP $cf_ip is reachable — walled garden not port-restricted!"
        record FAIL "CF port restriction" "TCP 8080 to $cf_ip accessible — only 80/443 should be allowed to CF IPs"
      else
        ok "Non-standard port (8080) to Cloudflare IP blocked."
        record PASS "CF port restriction" "TCP 8080 to CF IP $cf_ip blocked"
      fi
    fi

  else
    header "TEST 7 — Walled Garden Scope"
    log "Portal is NOT on Cloudflare — running generic walled garden scope check."

    # Generic test: a random internet site should NOT be reachable pre-auth
    local test_sites=("example.com" "wikipedia.org" "github.com")
    local accessible=0
    for site in "${test_sites[@]}"; do
      if curl -s --max-time 5 --head "https://${site}" &>/dev/null; then
        fail "https://${site} is reachable pre-auth — walled garden may be too open!"
        record FAIL "Walled garden scope" "${site} accessible pre-auth — internet not fully blocked"
        accessible=1
        break
      fi
    done
    if [ "$accessible" -eq 0 ]; then
      ok "Random internet sites blocked — walled garden scope is correct."
      record PASS "Walled garden scope" "Tested sites unreachable pre-auth"
    fi

    record SKIP "CF port restriction" "Portal not on Cloudflare — not applicable"
    record SKIP "CF walled garden scope" "Portal not on Cloudflare — not applicable"
  fi
}

# ── TEST 8: Portal Integrity ──────────────────────────────────
test_portal_integrity() {
  header "TEST 8 — Portal & Walled Garden Integrity"

  # Ensure the portal itself still loads correctly after all our rules
  local slugs=("${PORTAL_DOMAIN}" "www.${PORTAL_DOMAIN}")

  for domain in "${slugs[@]}"; do
    local scheme="https"
    [[ "$domain" == *".local" ]] && scheme="http"
    log "Testing portal access: ${scheme}://${domain}..."
    local http_code
    # shellcheck disable=SC2086
    http_code=$(curl -s --max-time "$TIMEOUT" $PORTAL_CURL_RESOLVE \
      -o /dev/null -w "%{http_code}" "${scheme}://${domain}" 2>/dev/null)
    if [[ "$http_code" =~ ^(200|301|302|307|308)$ ]]; then
      ok "Portal ${domain} → HTTP ${http_code} (accessible)."
      record PASS "Portal integrity" "${domain} returned HTTP ${http_code}"
    else
      fail "Portal ${domain} returned HTTP ${http_code} — may be broken."
      record FAIL "Portal integrity" "${domain} returned HTTP ${http_code}"
    fi
  done

  # Payment gateway must be reachable pre-auth (customers need to pay before getting a voucher)
  log "Testing payment gateway walled garden: ${PAYMENT_DOMAIN}..."
  log "(Override with: PAYMENT_DOMAIN=api.stripe.com bash bypass-test.sh)"
  if curl -s --max-time "$TIMEOUT" --head "https://${PAYMENT_DOMAIN}" &>/dev/null; then
    ok "Payment gateway reachable: ${PAYMENT_DOMAIN} — walled garden intact."
    record PASS "Payment gateway walled garden" "${PAYMENT_DOMAIN} accessible pre-auth"
  else
    warn "${PAYMENT_DOMAIN} not reachable — customers may not be able to pay before auth."
    record WARN "Payment gateway walled garden" "${PAYMENT_DOMAIN} unreachable pre-auth"
  fi
}

# ── TEST 9: Stateful Firewall ─────────────────────────────────
test_stateful_firewall() {
  header "TEST 9 — Stateful Firewall (TCP State Confusion)"
  log "Checking that stray ACK/RST packets can't bypass the firewall..."

  if [ -z "$HPING_CMD" ] && ! command -v nmap &>/dev/null; then
    skip "hping3/hping and nmap not installed — skipping stateful firewall test."
    record SKIP "Stateful firewall" "hping3/nmap not available"
    return
  fi

  if ! is_root && ! can_sudo; then
    skip "Stateful firewall test requires root/sudo — skipping."
    record SKIP "Stateful firewall" "Root required but not available"
    return
  fi

  # ── Method A: hping3/hping (most accurate) ──────────────────
  if [ -n "$HPING_CMD" ]; then

    # SYN: new connection to internet — must be blocked
    log "$HPING_CMD SYN → $EXTERNAL_IP:443 (new connection — must be BLOCKED)..."
    local syn_log; syn_log=$(mktemp /tmp/hping3_syn.XXXXXX)
    ${SUDO} ${TIMEOUT_CMD:-timeout} 8 $HPING_CMD -c 3 -S -p 443 -n "$EXTERNAL_IP" > "$syn_log" 2>&1 || true
    local syn_out; syn_out=$(cat "$syn_log"); rm -f "$syn_log"

    if echo "$syn_out" | grep -qi "flags=SA"; then
      fail "TCP SYN got SYN-ACK from $EXTERNAL_IP:443 — internet is reachable without auth!"
      record FAIL "TCP SYN blocked" "$HPING_CMD SYN got SA reply — internet reachable"
    else
      ok "TCP SYN dropped — new connections to internet are blocked."
      record PASS "TCP SYN blocked" "No SYN-ACK received from $EXTERNAL_IP:443"
    fi

    # ACK: spoofed "established" session — should ALSO be blocked
    log "$HPING_CMD ACK → $EXTERNAL_IP:443 (spoofed established — must also be BLOCKED)..."
    local ack_log; ack_log=$(mktemp /tmp/hping3_ack.XXXXXX)
    ${SUDO} ${TIMEOUT_CMD:-timeout} 8 $HPING_CMD -c 3 -A -p 443 -n "$EXTERNAL_IP" > "$ack_log" 2>&1 || true
    local ack_out; ack_out=$(cat "$ack_log"); rm -f "$ack_log"

    if echo "$ack_out" | grep -qi "flags=RA\|flags=R\b"; then
      # RST back from router means it was blocked at the router — good
      ok "TCP ACK got RST — router blocked stray ACK (stateful firewall working)."
      record PASS "Stateful firewall (ACK)" "Stray ACK to $EXTERNAL_IP:443 → RST from router"
    elif echo "$ack_out" | grep -qi "100% packet loss\|timeout"; then
      ok "TCP ACK silently dropped — stateful firewall is blocking stray packets."
      record PASS "Stateful firewall (ACK)" "Stray ACK to $EXTERNAL_IP:443 dropped"
    elif echo "$ack_out" | grep -qi "flags=SA\|flags=A"; then
      fail "TCP ACK got a real response from $EXTERNAL_IP — stray packets routed through!"
      fail "Firewall is NOT checking connection state — established/related trap exists."
      record FAIL "Stateful firewall (ACK)" "Stray ACK to $EXTERNAL_IP:443 received response — state bypass possible"
    else
      warn "TCP ACK result inconclusive — check MikroTik connection-tracking rules manually."
      record WARN "Stateful firewall (ACK)" "hping3 ACK output inconclusive"
    fi
    return
  fi

  # ── Method B: nmap ACK scan (fallback) ──────────────────────
  if command -v nmap &>/dev/null; then
    log "nmap ACK scan → $EXTERNAL_IP:443 (checking if stateful rules are in place)..."
    local nmap_out
    nmap_out=$(${SUDO} nmap -n --scanflags ACK -p 443 --host-timeout 12s "$EXTERNAL_IP" 2>/dev/null \
               | grep "443/tcp" || true)

    if echo "$nmap_out" | grep -q "unfiltered"; then
      fail "nmap: port 443 shows 'unfiltered' for ACK scan — stray TCP ACK getting through!"
      record FAIL "Stateful firewall (ACK)" "nmap ACK scan: $EXTERNAL_IP:443 unfiltered"
    elif echo "$nmap_out" | grep -q "filtered"; then
      ok "nmap: port 443 'filtered' — stateful firewall blocking stray ACK packets."
      record PASS "Stateful firewall (ACK)" "nmap ACK scan: $EXTERNAL_IP:443 filtered"
    else
      warn "nmap ACK scan result: '${nmap_out:-no output}' — inconclusive."
      record WARN "Stateful firewall (ACK)" "nmap ACK scan inconclusive: ${nmap_out:-no output}"
    fi
  fi
}

# ── TEST 10: DNS Hijacking ────────────────────────────────────
test_dns_hijacking() {
  header "TEST 10 — DNS Hijacking & Leak Verification"

  if ! command -v dig &>/dev/null; then
    skip "dig not installed — skipping DNS hijacking test."
    record SKIP "DNS hijacking check" "dig not available"
    return
  fi

  # Test 10a: NXDOMAIN — non-existent domain must return NXDOMAIN, not a portal IP
  local fake_domain="rcn-test-nxdomain-$(date +%s)-xyzabc.invalid"
  log "Querying non-existent domain '$fake_domain' — must return NXDOMAIN..."
  local nxdomain_raw nxdomain_ip nxdomain_status
  nxdomain_raw=$(dig +short +time=5 @"$ROUTER_IP" "$fake_domain" 2>/dev/null)
  # Extract only real IPv4 addresses — dig on Android outputs error lines to stdout too
  nxdomain_ip=$(echo "$nxdomain_raw" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
  nxdomain_status=$(dig +time=5 @"$ROUTER_IP" "$fake_domain" 2>/dev/null \
                    | awk '/status:/{gsub(",",""); print $6}' | head -1)

  if [ -n "$nxdomain_ip" ]; then
    # An actual IP was returned for a non-existent domain = hijacked
    fail "Router returned IP '$nxdomain_ip' for a non-existent domain — NXDOMAIN hijack!"
    warn "All failed lookups redirect to: $nxdomain_ip"
    warn "This breaks iOS/Android captive portal detection and some auth apps."
    record FAIL "DNS NXDOMAIN correct" "Fake domain resolved to $nxdomain_ip — NXDOMAIN hijacked"
  elif [ -z "$nxdomain_raw" ] || echo "$nxdomain_raw" | grep -qi "timed out\|communications error\|SERVFAIL\|no servers"; then
    # Timeout/error = DNS has issues but no hijacking
    warn "DNS query for fake domain timed out — router DNS may have issues, but no hijacking detected."
    record WARN "DNS NXDOMAIN correct" "Query timed out (no hijack, but DNS reliability issue)"
  elif [ "$nxdomain_status" = "NXDOMAIN" ]; then
    ok "Router returns correct NXDOMAIN — DNS not hijacking unknown queries."
    record PASS "DNS NXDOMAIN correct" "Router returned NXDOMAIN for $fake_domain"
  else
    warn "DNS response for fake domain unclear (status: ${nxdomain_status:-none}) — check manually."
    record WARN "DNS NXDOMAIN correct" "Status ${nxdomain_status:-unknown} for $fake_domain"
  fi

  # Test 10b: Verify router answers as resolver (not just transparent passthrough)
  log "Verifying router $ROUTER_IP responds to DNS queries directly..."
  local direct_answer
  direct_answer=$(dig +short +time=5 @"$ROUTER_IP" "$EXTERNAL_HOST" 2>/dev/null | head -1)
  if [ -n "$direct_answer" ]; then
    ok "Router at $ROUTER_IP answers DNS directly — resolver role confirmed."
    record PASS "Router as DNS resolver" "$ROUTER_IP resolved $EXTERNAL_HOST → $direct_answer"
  else
    warn "Router $ROUTER_IP did not answer DNS — check /ip dns allow-remote-requests=yes."
    record WARN "Router as DNS resolver" "No DNS response from $ROUTER_IP directly"
  fi

  # Test 10c: DNS redirect — proof via an unreachable nameserver
  # Logic: 192.0.2.1 is TEST-NET-1, reserved and unroutable — it is never a real resolver.
  # WITHOUT redirect: query to @192.0.2.1 times out (packet can't reach it).
  # WITH redirect: router's NAT rule intercepts the query before it leaves and answers
  #   it locally — so it resolves successfully. Success here is PROOF redirect is on.
  # Note: querying @8.8.8.8 is NOT used here because with redirect on, 8.8.8.8 also
  # resolves (router intercepts it) — making success vs. timeout ambiguous.
  local unreachable_ns="192.0.2.1"
  log "Confirming DNS redirect using unreachable nameserver ($unreachable_ns)..."
  log "(Resolving via $unreachable_ns is only possible if the router intercepts the query)"
  local redirect_proof
  redirect_proof=$(dig +short +time=6 @"$unreachable_ns" "$EXTERNAL_HOST" 2>/dev/null | head -1)
  if [ -n "$redirect_proof" ]; then
    ok "DNS resolved '$redirect_proof' via unreachable NS — router is intercepting all DNS."
    ok "DNS NAT redirect is definitively confirmed active."
    record PASS "DNS redirect confirmed" "Unreachable NS $unreachable_ns answered by router — redirect proven"
  else
    warn "Query to unreachable NS $unreachable_ns timed out — redirect may not be active."
    warn "Check MikroTik: /ip firewall nat print | grep dns-redirect"
    record WARN "DNS redirect confirmed" "Unreachable NS test inconclusive — verify NAT redirect rules"
  fi
}

# ── TEST 11: HTTP Header Injection ───────────────────────────
test_header_injection() {
  header "TEST 11 — HTTP Header Injection (Portal Identity Bypass)"

  local portal_url="${PORTAL_BASE_URL}"

  # Test 11a: X-Forwarded-For spoofing — portal must return same content regardless
  log "Testing X-Forwarded-For / X-Real-IP spoofing..."
  local normal_code spoofed_code
  # shellcheck disable=SC2086
  normal_code=$(curl -s --max-time "$TIMEOUT" $PORTAL_CURL_RESOLVE \
    -o /dev/null -w "%{http_code}" "$portal_url" 2>/dev/null)
  # shellcheck disable=SC2086
  spoofed_code=$(curl -s --max-time "$TIMEOUT" $PORTAL_CURL_RESOLVE \
    -o /dev/null -w "%{http_code}" \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Real-IP: 127.0.0.1" \
    -H "X-Originating-IP: 127.0.0.1" \
    -H "CF-Connecting-IP: 127.0.0.1" \
    "$portal_url" 2>/dev/null)

  if [ "$normal_code" = "$spoofed_code" ]; then
    ok "Portal returns HTTP $normal_code with or without spoofed IP headers — not trusting XFF."
    record PASS "X-Forwarded-For ignored" "Same HTTP $normal_code with/without spoofed XFF headers"
  else
    fail "Portal response changed: normal=$normal_code, spoofed=$spoofed_code"
    fail "Portal may trust X-Forwarded-For for auth — IP spoofing bypass possible!"
    record FAIL "X-Forwarded-For ignored" "Response: $normal_code → $spoofed_code with spoofed XFF"
  fi

  # Test 11b: HTTP CONNECT method — portal must NOT act as a forward proxy
  log "Testing HTTP CONNECT method (portal must not proxy external requests)..."
  local connect_code
  # shellcheck disable=SC2086
  connect_code=$(curl -s --max-time "$TIMEOUT" $PORTAL_CURL_RESOLVE \
    -o /dev/null -w "%{http_code}" \
    -X CONNECT \
    -H "Host: google.com:443" \
    "$portal_url" 2>/dev/null)

  if [ "$connect_code" = "200" ]; then
    fail "Portal returned HTTP 200 to CONNECT method — may be acting as open HTTP proxy!"
    record FAIL "CONNECT proxy blocked" "Portal returned 200 to CONNECT method — proxy bypass risk"
  elif [[ "$connect_code" =~ ^(400|403|405|501|503|000)$ ]]; then
    ok "Portal rejected CONNECT method (HTTP $connect_code) — not a proxy."
    record PASS "CONNECT proxy blocked" "Portal returned HTTP $connect_code to CONNECT method"
  else
    warn "CONNECT method returned HTTP $connect_code — verify manually."
    record WARN "CONNECT proxy blocked" "CONNECT → HTTP $connect_code"
  fi

  # Test 11c: Spoofed Origin / Referer — check portal isn't doing naive origin checks
  log "Testing spoofed Origin header (portal must validate sessions, not headers)..."
  local origin_code
  # shellcheck disable=SC2086
  origin_code=$(curl -s --max-time "$TIMEOUT" $PORTAL_CURL_RESOLVE \
    -o /dev/null -w "%{http_code}" \
    -H "Origin: ${PORTAL_BASE_URL}" \
    -H "Referer: ${PORTAL_BASE_URL}/login" \
    "${portal_url}/api/usage" 2>/dev/null)

  if [[ "$origin_code" =~ ^(401|403|302|404)$ ]]; then
    # 404 = endpoint doesn't exist = not exploitable via origin spoofing
    ok "API with spoofed Origin returned HTTP $origin_code — origin spoofing not effective."
    record PASS "Origin header ignored" "API returned HTTP $origin_code — origin spoofing blocked"
  elif [ "$origin_code" = "200" ]; then
    warn "API returned 200 with spoofed Origin — confirm this endpoint requires a valid session token."
    record WARN "Origin header ignored" "API returned 200 with spoofed Origin — verify session enforcement"
  else
    warn "API with spoofed Origin: HTTP $origin_code — inconclusive."
    record WARN "Origin header ignored" "HTTP $origin_code — check manually"
  fi
}

# ── TEST 12: NTP Tunnel Bypass ────────────────────────────────
test_ntp_bypass() {
  header "TEST 12 — NTP Tunnel Bypass (UDP port 123)"
  log "NTP (UDP 123) should only reach the router's own clock — not the full internet..."

  # ── Method A: Python (most reliable) ────────────────────────
  if [ -n "$PYTHON_CMD" ]; then
    log "Sending real NTP client requests to external time servers..."
    local ntp_result
    ntp_result=$($PYTHON_CMD -c "
import socket

ntp_msg = b'\\x1b' + b'\\x00' * 47  # NTP mode 3 (client) request

targets = [
    ('216.239.35.0',   'time.google.com'),
    ('162.159.200.1',  'time.cloudflare.com'),
    ('129.6.15.28',    'time.nist.gov'),
]

reachable = []
for ip, name in targets:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(ntp_msg, (ip, 123))
        data, _ = s.recvfrom(1024)
        if len(data) >= 48:
            reachable.append(name)
    except:
        pass
    finally:
        s.close()

print('REACHABLE:' + ','.join(reachable) if reachable else 'BLOCKED')
" 2>/dev/null)

    if echo "$ntp_result" | grep -q "^REACHABLE:"; then
      local reached; reached=$(echo "$ntp_result" | cut -d: -f2)
      fail "NTP reached external servers: $reached"
      fail "UDP 123 is open to internet — usable as a low-bandwidth covert channel."
      warn "Fix: in MikroTik, add a forward/drop rule for UDP dst-port=123 from hotspot clients."
      record FAIL "NTP tunnel blocked" "UDP 123 reached: $reached — NTP bypass possible"
    else
      ok "All external NTP servers unreachable — UDP 123 is blocked to internet."
      record PASS "NTP tunnel blocked" "UDP 123 to all test NTP servers timed out"
    fi
    return
  fi

  # ── Method B: nc fallback ────────────────────────────────────
  if command -v nc &>/dev/null; then
    log "Testing NTP via netcat (UDP 123 → 216.239.35.0)..."
    printf '\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
      | nc -u -w 5 216.239.35.0 123 > /tmp/ntp_probe.bin 2>/dev/null || true
    local ntp_bytes; ntp_bytes=$(wc -c < /tmp/ntp_probe.bin 2>/dev/null || echo 0)
    rm -f /tmp/ntp_probe.bin

    if [ "$ntp_bytes" -ge 48 ]; then
      fail "NTP probe received $ntp_bytes bytes — UDP 123 is open to internet!"
      record FAIL "NTP tunnel blocked" "nc UDP 123 got $ntp_bytes bytes — NTP bypass possible"
    else
      ok "NTP probe got no response — UDP 123 appears blocked."
      record PASS "NTP tunnel blocked" "nc UDP 123 to 216.239.35.0 got no response"
    fi
    return
  fi

  skip "python3 and nc not available — skipping NTP test."
  record SKIP "NTP tunnel blocked" "No suitable tool available"
}

# ── Install check ─────────────────────────────────────────────
check_tools() {
  header "Checking Required Tools"

  # ── Always required ──────────────────────────────────────────
  check_tool "curl" "curl"
  check_tool "dig"  "dnsutils"

  # ── ping: pre-installed on macOS; via inetutils on Termux ───
  if [ "$PLATFORM" = "macos" ]; then
    command -v ping &>/dev/null && ok "ping pre-installed" || warn "ping not found on macOS"
  else
    check_tool "ping" "iputils-ping" || true
  fi

  # ── ip: not native on macOS (iproute2mac optional) ──────────
  if [ "$PLATFORM" != "macos" ]; then
    check_tool "ip" "iproute2" || true
  fi

  # ── nc: pre-installed on macOS ───────────────────────────────
  if [ "$PLATFORM" != "macos" ]; then
    check_tool "nc" "netcat-openbsd" || true
  fi

  # ── python: 'python3' on Linux/macOS, 'python' on Termux ────
  if [ "$PLATFORM" = "termux" ]; then
    check_tool "python" "python" || true
  else
    check_tool "python3" "python3" || true
  fi

  # ── kdig for DoT test ────────────────────────────────────────
  check_tool "kdig" "knot-dnsutils" || true

  # ── nmap: available on all platforms including Termux ────────
  check_tool "nmap" "nmap" || true

  # ── hping3: NOT in Termux repos — skip entirely, use nmap fallback
  if [ "$PLATFORM" = "termux" ]; then
    warn "hping3 not in Termux repos — TEST 9 will use nmap fallback"
  else
    check_tool "hping3" "hping3" || true
  fi

  # ── iodine: NOT in Termux repos — skip entirely
  if [ "$PLATFORM" = "termux" ]; then
    warn "iodine not in Termux repos — TEST 6 will be skipped"
  else
    check_tool "iodine" "iodine" || true
  fi

  install_tools
}

# ── Telemetry ─────────────────────────────────────────────────
send_telemetry() {
  [ -z "$TELEMETRY_URL" ] && return

  log "Sending audit results to telemetry endpoint..."
  local entries=""
  local first=1
  for entry in "${RESULTS[@]}"; do
    IFS='|' read -r status name detail <<< "$entry"
    [ $first -eq 0 ] && entries+=","
    entries+=$(printf '{"status":"%s","name":"%s","detail":"%s"}' \
      "$status" "$name" "$(echo "$detail" | sed 's/"/\\"/g')")
    first=0
  done

  local payload
  payload=$(printf '{"event":"captive_portal_audit","portal":"%s","pass":%d,"fail":%d,"warn":%d,"skip":%d,"date":"%s","results":[%s]}' \
    "$PORTAL_DOMAIN" "$PASS" "$FAIL" "$WARN" "$SKIP" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$entries")

  if curl -s --max-time 10 -X POST \
      -H "Content-Type: application/json" \
      -d "$payload" \
      "$TELEMETRY_URL" &>/dev/null; then
    ok "Audit results posted to: $TELEMETRY_URL"
  else
    warn "Could not reach telemetry endpoint: $TELEMETRY_URL"
  fi
}

# ── Summary ───────────────────────────────────────────────────
print_summary() {
  echo ""
  sep
  echo -e "${BOLD}  BYPASS TEST SUMMARY${NC}"
  sep
  printf "  %-40s %s\n" "Test" "Result"
  echo "  ────────────────────────────────────────────────────"
  for entry in "${RESULTS[@]}"; do
    IFS='|' read -r status name detail <<< "$entry"
    case "$status" in
      PASS) icon="${GREEN}✔ PASS${NC}" ;;
      FAIL) icon="${RED}✘ FAIL${NC}" ;;
      WARN) icon="${YELLOW}⚠ WARN${NC}" ;;
      SKIP) icon="${CYAN}- SKIP${NC}" ;;
    esac
    printf "  %-40s " "$name"
    echo -e "$icon"
  done
  echo ""
  sep
  echo -e "  ${GREEN}PASS: $PASS${NC}  |  ${RED}FAIL: $FAIL${NC}  |  ${YELLOW}WARN: $WARN${NC}  |  ${CYAN}SKIP: $SKIP${NC}"
  sep

  if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo -e "${RED}${BOLD}  ✘ $FAIL test(s) FAILED — bypasses are possible.${NC}"
    echo -e "  Review FAIL entries above and apply the recommended firewall rules"
    echo -e "  for your platform (MikroTik, OpenWRT, pfSense, etc.)."
    send_telemetry
  elif [ "$WARN" -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}${BOLD}  ⚠ $WARN warning(s) — minor issues or known limitations.${NC}"
    echo -e "  Review WARN entries — most are minor or platform limitations (e.g. Android ICMP needs root)."
  else
    echo ""
    echo -e "${GREEN}${BOLD}  ✔ All tests passed — captive portal hardening is working!${NC}"
  fi

  # Firewall order confirmation — if all protocol-block tests passed, the drop rules
  # are provably executing before any walled-garden accept rules in the chain.
  local icmp_ok dot_ok quic_ok
  icmp_ok=$(printf '%s\n' "${RESULTS[@]}" | grep "ICMP tunnel block" | grep -c "^PASS" || true)
  dot_ok=$(printf '%s\n'  "${RESULTS[@]}" | grep "DoT blocked"       | grep -c "^PASS" || true)
  quic_ok=$(printf '%s\n' "${RESULTS[@]}" | grep "QUIC blocked"      | grep -c "^PASS" || true)
  if [ "${icmp_ok:-0}" -gt 0 ] && [ "${dot_ok:-0}" -gt 0 ] && [ "${quic_ok:-0}" -gt 0 ]; then
    echo ""
    echo -e "${GREEN}  ✔ Firewall rule ordering confirmed${NC} — ICMP/DoT/QUIC drop rules"
    echo -e "    are evaluated before walled-garden accept rules (all three blocked)."
  fi

  if [ "$PORTAL_ON_CLOUDFLARE" -eq 1 ]; then
    echo ""
    echo -e "${BOLD}  Known unfixable limitation (Cloudflare-hosted portal):${NC}"
    echo -e "  WebSocket proxy over HTTPS (port 443) via any Cloudflare-hosted"
    echo -e "  site remains theoretically possible. Mitigated by: rate-limiting,"
    echo -e "  the need for a Cloudflare account, and slow tunnel throughput."
  fi
  echo ""
}

# ── Main ──────────────────────────────────────────────────────
main() {
  clear
  echo ""
  echo -e "${BOLD}${BLUE}  ╔══════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${BLUE}  ║   Captive Portal Bypass Test Suite v2.6      ║${NC}"
  echo -e "${BOLD}${BLUE}  ║   Connect to hotspot (unauthenticated) first  ║${NC}"
  echo -e "${BOLD}${BLUE}  ╚══════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "  Payment: ${CYAN}${PAYMENT_DOMAIN}${NC}"
  echo -e "  Target:  ${CYAN}${EXTERNAL_IP}${NC}"
  echo -e "  Date:    ${CYAN}$(date)${NC}"
  echo ""

  detect_platform
  detect_portal_domain
  echo -e "  Portal:  ${CYAN}${PORTAL_DOMAIN:-not detected}${NC}"
  echo ""
  check_tools
  setup_commands
  preflight
  test_ipv6
  test_icmp
  test_dot
  test_quic
  test_dns_redirect
  test_dns_tunnel
  test_cf_walled_garden
  test_portal_integrity
  test_stateful_firewall
  test_dns_hijacking
  test_header_injection
  test_ntp_bypass
  print_summary
}

main "$@"
