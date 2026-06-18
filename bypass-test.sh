#!/usr/bin/env bash
# ============================================================
#  RuralConnect — Captive Portal Bypass Test Suite
#  Version: 1.0  |  Date: 2026-06-18
#
#  PURPOSE: Verify that all captive portal bypass defenses are
#           working correctly on a deployed RuralConnect router.
#
#  HOW TO USE:
#    1. Connect a device to the hotspot WiFi
#    2. Do NOT authenticate / enter a voucher code yet
#    3. Run:  bash bypass-test.sh
#    4. Review the PASS/FAIL summary at the end
#
#  PLATFORMS: Linux, Termux (Android), macOS
#  NOTE:      Some tests require root/sudo (iodine, raw ICMP).
#             On Termux, run without sudo.
# ============================================================

# ── Colours ─────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[1;34m'; CYAN='\033[0;36m';  BOLD='\033[1m'; NC='\033[0m'

# ── Config ───────────────────────────────────────────────────
PORTAL_DOMAIN="${PORTAL_DOMAIN:-rcnetworks.xyz}"      # override with env if needed
EXTERNAL_IP="8.8.8.8"                                 # IP that should be unreachable pre-auth
EXTERNAL_HOST="google.com"
DNS_TUNNEL_SANDBOX="sandbox.iodine.kryo.se"           # public iodine test server
ROUTER_IP="192.168.88.1"                              # default RuralConnect hotspot gateway
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

is_root() { [ "$(id -u)" -eq 0 ]; }
can_sudo() { command -v sudo &>/dev/null && sudo -n true 2>/dev/null; }

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
      $SUDO apt-get update -qq
      for pkg in "${MISSING_TOOLS[@]}"; do
        $SUDO apt-get install -y -qq "$pkg" && log "Installed: $pkg" || warn "Failed to install: $pkg"
      done
      ;;
    fedora|rhel)
      for pkg in "${MISSING_TOOLS[@]}"; do
        $SUDO "$PKG_MGR" install -y -q "$pkg" && log "Installed: $pkg" || warn "Failed to install: $pkg"
      done
      ;;
    termux)
      pkg update -y -q 2>/dev/null
      for pkg in "${MISSING_TOOLS[@]}"; do
        # Termux package names differ slightly
        local tpkg="$pkg"
        [[ "$pkg" == "dnsutils" ]] && tpkg="dnsutils"
        [[ "$pkg" == "knot-dnsutils" ]] && tpkg="knot-utils"
        [[ "$pkg" == "iodine" ]] && tpkg="iodine"
        pkg install -y "$tpkg" 2>/dev/null && log "Installed: $tpkg" || warn "Not available in Termux: $tpkg"
      done
      ;;
    macos)
      for pkg in "${MISSING_TOOLS[@]}"; do
        local mpkg="$pkg"
        [[ "$pkg" == "dnsutils" ]] && mpkg="bind"
        [[ "$pkg" == "knot-dnsutils" ]] && mpkg="knot-dns"
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

  # Check we have a gateway (connected to something)
  if ! ip route &>/dev/null 2>&1 && ! route -n &>/dev/null 2>&1; then
    fail "No network interface found. Are you connected to WiFi?"
    exit 1
  fi

  # Try to detect the router IP
  local gw
  gw=$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')
  if [ -n "$gw" ]; then
    ROUTER_IP="$gw"
    log "Gateway detected: $ROUTER_IP"
  else
    warn "Could not auto-detect gateway, using default: $ROUTER_IP"
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
  if curl -s --max-time 8 --head "https://${PORTAL_DOMAIN}" &>/dev/null; then
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
  local ipv6_global
  ipv6_global=$(ip -6 addr show 2>/dev/null | grep "inet6" | grep -v " fe80" | grep -v " ::1" | head -1)

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
  if ping -c 2 -W 3 "$ROUTER_IP" &>/dev/null 2>&1; then
    ok "Small ICMP to router works (expected)."
    record PASS "ICMP small (≤64B)" "ping to $ROUTER_IP succeeded"
  else
    warn "Small ICMP to router failed — may be a firewall issue unrelated to tunneling."
    record WARN "ICMP small (≤64B)" "ping to $ROUTER_IP failed — check if ICMP is globally blocked"
  fi

  # Test 2b: Large ping to external — must be DROPPED (tunnel prevention)
  log "Testing oversized ICMP (500 bytes) to internet — should be DROPPED..."
  local large_result=0

  if is_root || can_sudo; then
    # Linux: -s sets data size (500 bytes data + 28 header = 528 bytes total)
    if ${SUDO} ping -c 2 -W "$TIMEOUT" -s 500 "$EXTERNAL_IP" &>/dev/null 2>&1; then
      large_result=1
    fi
  else
    # Try without sudo (works on most modern Linux and macOS)
    if ping -c 2 -W "$TIMEOUT" -s 500 "$EXTERNAL_IP" &>/dev/null 2>&1; then
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
  if ping -c 2 -W 5 -s 150 "$ROUTER_IP" &>/dev/null 2>&1; then
    ok "Medium ICMP (150B) to router works — threshold is correct."
    record PASS "ICMP threshold (150B)" "ping -s 150 passes as expected"
  else
    warn "Medium ICMP (150B) failed — threshold may be too aggressive."
    record WARN "ICMP threshold (150B)" "ping -s 150 failed — may cause diagnostic issues"
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
  if command -v python3 &>/dev/null; then
    log "Testing QUIC via Python UDP probe (UDP 443 to $EXTERNAL_IP)..."
    local py_result
    py_result=$(python3 -c "
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

  skip "No HTTP/3-capable curl, python3, or nc available — skipping QUIC test."
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

  ${SUDO} timeout "$IODINE_TIMEOUT" iodine -f -r -P autodie \
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

  # Cleanup: remove tun device if iodine created one
  ${SUDO} ip link delete dns0 2>/dev/null || true
}

# ── TEST 7: Cloudflare Walled Garden Scope ────────────────────
test_cf_walled_garden() {
  header "TEST 7 — Cloudflare Walled Garden Scope"

  log "Testing that a random Cloudflare-hosted site is NOT freely accessible..."

  # Cloudflare Pages / Workers — attacker could host a proxy here
  # This should be accessible (TCP 443) but NOT tunnelable beyond HTTP
  # We test if raw non-HTTP traffic on port 443 gets through

  local cf_test_domain="cloudflare-eth.com"  # Cloudflare-hosted, not our portal

  if curl -s --max-time "$TIMEOUT" --head "https://${cf_test_domain}" &>/dev/null; then
    warn "Cloudflare-hosted site ${cf_test_domain} is accessible (TCP 443)."
    warn "This is EXPECTED — we only block non-HTTP protocols on CF IPs."
    warn "A determined attacker could still use WebSocket over HTTPS as a proxy."
    warn "This is a known limitation of Cloudflare-based portal architecture."
    record WARN "CF walled garden scope" "${cf_test_domain} accessible via TCP 443 — WebSocket bypass theoretically possible"
  else
    ok "${cf_test_domain} not accessible — walled garden is very tight."
    record PASS "CF walled garden scope" "${cf_test_domain} not reachable pre-auth"
  fi

  # Test that non-HTTP CF traffic is blocked (e.g., a raw TCP connection on non-80/443 port)
  if command -v nc &>/dev/null; then
    log "Testing that non-standard ports to Cloudflare IPs are blocked..."
    local cf_ip="104.16.1.1"  # Known Cloudflare IP
    if nc -z -w 5 "$cf_ip" 8080 &>/dev/null 2>&1; then
      fail "Port 8080 to Cloudflare IP $cf_ip is reachable — walled garden not port-restricted!"
      record FAIL "CF port restriction" "TCP 8080 to $cf_ip accessible — only 80/443 should be allowed"
    else
      ok "Non-standard port (8080) to Cloudflare IP blocked."
      record PASS "CF port restriction" "TCP 8080 to CF IP $cf_ip blocked"
    fi
  fi
}

# ── TEST 8: Portal Integrity ──────────────────────────────────
test_portal_integrity() {
  header "TEST 8 — Portal & Walled Garden Integrity"

  # Ensure the portal itself still loads correctly after all our rules
  local slugs=("${PORTAL_DOMAIN}" "www.${PORTAL_DOMAIN}")

  for domain in "${slugs[@]}"; do
    log "Testing portal access: https://${domain}..."
    local http_code
    http_code=$(curl -s --max-time "$TIMEOUT" -o /dev/null -w "%{http_code}" "https://${domain}" 2>/dev/null)
    if [[ "$http_code" =~ ^(200|301|302|307|308)$ ]]; then
      ok "Portal ${domain} → HTTP ${http_code} (accessible)."
      record PASS "Portal integrity" "${domain} returned HTTP ${http_code}"
    else
      fail "Portal ${domain} returned HTTP ${http_code} — may be broken."
      record FAIL "Portal integrity" "${domain} returned HTTP ${http_code}"
    fi
  done

  # Paystack (payment gateway) must be reachable pre-auth
  log "Testing Paystack payment gateway (must be in walled garden)..."
  if curl -s --max-time "$TIMEOUT" --head "https://api.paystack.co" &>/dev/null; then
    ok "Paystack API reachable — payment walled garden intact."
    record PASS "Paystack walled garden" "api.paystack.co accessible pre-auth"
  else
    warn "Paystack not reachable — customers may not be able to pay before voucher entry."
    record WARN "Paystack walled garden" "api.paystack.co unreachable pre-auth"
  fi
}

# ── Install check ─────────────────────────────────────────────
check_tools() {
  header "Checking Required Tools"

  check_tool "curl"    "curl"
  check_tool "ping"    "iputils-ping"
  check_tool "dig"     "dnsutils"
  check_tool "ip"      "iproute2"
  check_tool "kdig"    "knot-dnsutils"   || true
  check_tool "iodine"  "iodine"          || true
  check_tool "nc"      "netcat-openbsd"  || true
  check_tool "python3" "python3"         || true

  install_tools
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
    echo -e "  Review FAIL entries above and check router scripts version."
    echo -e "  Routers must be on scripts v52+ for full hardening."
  elif [ "$WARN" -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}${BOLD}  ⚠ $WARN warning(s) — minor issues or known limitations.${NC}"
    echo -e "  Most WARNs are expected (e.g. WebSocket-over-443 is unfixable)."
  else
    echo ""
    echo -e "${GREEN}${BOLD}  ✔ All tests passed — captive portal hardening is working!${NC}"
  fi

  echo ""
  echo -e "${BOLD}  Known unfixable limitation:${NC}"
  echo -e "  WebSocket proxy over HTTPS (port 443) via any Cloudflare-hosted"
  echo -e "  site remains theoretically possible. Mitigated by: rate-limiting,"
  echo -e "  the need for a Cloudflare account, and slow tunnel throughput."
  echo ""
}

# ── Main ──────────────────────────────────────────────────────
main() {
  clear
  echo ""
  echo -e "${BOLD}${BLUE}  ╔══════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${BLUE}  ║   RuralConnect Bypass Test Suite v1.0        ║${NC}"
  echo -e "${BOLD}${BLUE}  ║   Connect to hotspot (unauthenticated) first  ║${NC}"
  echo -e "${BOLD}${BLUE}  ╚══════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "  Portal: ${CYAN}${PORTAL_DOMAIN}${NC}"
  echo -e "  Target: ${CYAN}${EXTERNAL_IP}${NC}"
  echo -e "  Date:   ${CYAN}$(date)${NC}"
  echo ""

  detect_platform
  check_tools
  preflight
  test_ipv6
  test_icmp
  test_dot
  test_quic
  test_dns_redirect
  test_dns_tunnel
  test_cf_walled_garden
  test_portal_integrity
  print_summary
}

main "$@"
