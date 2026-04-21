#!/bin/bash
# ============================================================================
# KahLuna WARP Gateway -- Functional Test Suite
# Run this on the deployed gateway to verify all major features.
# Usage: bash tests/functional_test.sh
# ============================================================================
set -uo pipefail

PASS=0
FAIL=0
SKIP=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAIL++)); }
skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; ((SKIP++)); }
section() { echo ""; echo -e "${CYAN}--- $1 ---${NC}"; echo ""; }

# ── Determine paths ──────────────────────────────────────────────────────────

GATEWAY_DIR="${GATEWAY_DIR:-/opt/warp-gateway}"
VENV="${GATEWAY_DIR}/venv/bin"

if [ ! -f "${GATEWAY_DIR}/gateway.py" ]; then
    echo "ERROR: gateway.py not found at ${GATEWAY_DIR}"
    echo "Set GATEWAY_DIR to the warp-gateway installation path."
    exit 1
fi

cd "$GATEWAY_DIR"

if [ ! -f "${VENV}/python" ]; then
    echo "ERROR: Python venv not found at ${VENV}"
    exit 1
fi

PYTHON="${VENV}/python"

echo ""
echo "============================================================"
echo "  KahLuna WARP Gateway -- Functional Test Suite"
echo "============================================================"
echo ""
echo "  Gateway: ${GATEWAY_DIR}"
echo "  Python:  ${PYTHON}"
echo ""

# ── Helper: run a Python snippet in the Flask app context ────────────────────

run_in_context() {
    local tmpfile=$(mktemp /tmp/warp_test_XXXXXX.py)
    cat > "$tmpfile" << PYEOF
import sys, os
sys.path.insert(0, '${GATEWAY_DIR}')
os.chdir('${GATEWAY_DIR}')
from gateway import create_app
app = create_app()
with app.app_context():
    $1
PYEOF
    $PYTHON "$tmpfile" 2>&1
    local rc=$?
    rm -f "$tmpfile"
    return $rc
}

# ============================================================================
# 1. DATABASE AND MODELS
# ============================================================================

section "Database and Models"

# Check database is accessible
result=$(run_in_context "
from database import db
from models_new import User, GatewayConfig
print('DB_OK')
")
if echo "$result" | grep -q "DB_OK"; then
    pass "Database accessible"
else
    fail "Database not accessible: $result"
fi

# Check GatewayConfig singleton
result=$(run_in_context "
from models_new import GatewayConfig
c = GatewayConfig.get_instance()
print(f'CONFIG:{c.hostname}:{c.management_mode}')
")
if echo "$result" | grep -q "CONFIG:"; then
    hostname=$(echo "$result" | grep "CONFIG:" | cut -d: -f2)
    mode=$(echo "$result" | grep "CONFIG:" | cut -d: -f3)
    pass "GatewayConfig singleton (hostname=${hostname}, mode=${mode})"
else
    fail "GatewayConfig singleton: $result"
fi

# Check admin user exists
result=$(run_in_context "
from models_new import User
u = User.query.filter_by(role='admin').first()
if u:
    print(f'ADMIN:{u.username}')
else:
    print('NO_ADMIN')
")
if echo "$result" | grep -q "ADMIN:"; then
    admin=$(echo "$result" | grep "ADMIN:" | cut -d: -f2)
    pass "Admin user exists (${admin})"
else
    fail "No admin user found"
fi

# ============================================================================
# 2. CLI SHELL
# ============================================================================

section "CLI Shell Components"

# Test command parser
result=$(run_in_context "
import cli.command_tree as ct
ct._TREES = None
from cli.parser import CommandParser
p = CommandParser()
r = p.parse('show interfaces', 'exec')
if r.resolved_node and r.path == ['show', 'interfaces']:
    print('PARSER_OK')
else:
    print(f'PARSER_FAIL:{r.error}:{r.path}')
")
if echo "$result" | grep -q "PARSER_OK"; then
    pass "Command parser (show interfaces)"
else
    fail "Command parser: $result"
fi

# Test abbreviation resolution
result=$(run_in_context "
import cli.command_tree as ct
ct._TREES = None
from cli.parser import CommandParser
p = CommandParser()
r = p.parse('sh int', 'exec')
if r.resolved_node and r.path == ['show', 'interfaces']:
    print('ABBREV_OK')
else:
    print(f'ABBREV_FAIL:{r.error}:{r.path}')
")
if echo "$result" | grep -q "ABBREV_OK"; then
    pass "Abbreviation resolution (sh int -> show interfaces)"
else
    fail "Abbreviation resolution: $result"
fi

# Test mode stack
result=$(run_in_context "
from cli.modes import ModeStack, EXEC, PRIVILEGED, CONFIGURE, CONFIG_IF
ms = ModeStack()
assert ms.current == EXEC
ms.push(PRIVILEGED)
assert ms.current == PRIVILEGED
ms.push(CONFIGURE)
ms.push(CONFIG_IF)
ms.reset_to(PRIVILEGED)
assert ms.current == PRIVILEGED
print('MODES_OK')
")
if echo "$result" | grep -q "MODES_OK"; then
    pass "Mode stack transitions"
else
    fail "Mode stack: $result"
fi

# Test output formatter
result=$(run_in_context "
from cli.formatter import OutputFormatter
fmt = OutputFormatter()
out = fmt.table(['Name', 'Value'], [['test', '123']])
if 'Name' in out and 'test' in out and '123' in out:
    # Check no trailing whitespace
    for line in out.split('\n'):
        if line != line.rstrip():
            print('TRAILING_WS')
            break
    else:
        print('FORMATTER_OK')
else:
    print('FORMATTER_FAIL')
")
if echo "$result" | grep -q "FORMATTER_OK"; then
    pass "Output formatter (table, no trailing whitespace)"
else
    fail "Output formatter: $result"
fi

# Test help system
result=$(run_in_context "
import cli.command_tree as ct
ct._TREES = None
from cli.help_system import HelpSystem
hs = HelpSystem()
out = hs.get_help('', 'exec')
if 'show' in out and 'ping' in out and 'enable' in out:
    print('HELP_OK')
else:
    print(f'HELP_FAIL:{out[:100]}')
")
if echo "$result" | grep -q "HELP_OK"; then
    pass "Help system (exec mode commands)"
else
    fail "Help system: $result"
fi

# ============================================================================
# 3. SERVICE LAYER
# ============================================================================

section "Service Layer"

# Test interface service
result=$(run_in_context "
from services.interface_service import get_all_interfaces
ifaces = get_all_interfaces()
print(f'IFACES:{len(ifaces)}')
for i in ifaces:
    print(f'  {i[\"name\"]} role={i[\"role\"]} ip={i.get(\"ip\", \"none\")}')
")
if echo "$result" | grep -q "IFACES:"; then
    count=$(echo "$result" | grep "IFACES:" | cut -d: -f2)
    pass "Interface service (${count} interfaces detected)"
else
    fail "Interface service: $result"
fi

# Test health service
result=$(run_in_context "
from services.health_service import get_system_health
h = get_system_health()
if 'cpu_percent' in h and 'memory' in h and 'disk' in h:
    print(f'HEALTH_OK:cpu={h[\"cpu_percent\"]}%,mem={h[\"memory\"][\"percent\"]}%')
else:
    print('HEALTH_FAIL')
")
if echo "$result" | grep -q "HEALTH_OK"; then
    pass "Health service ($(echo "$result" | grep "HEALTH_OK" | cut -d: -f2))"
else
    fail "Health service: $result"
fi

# Test config serializer
result=$(run_in_context "
from cli.config_serializer import ConfigSerializer
s = ConfigSerializer()
config = s.serialize_running_config()
if 'hostname' in config and 'end' in config:
    print(f'SERIALIZER_OK:{len(config)} bytes')
else:
    print('SERIALIZER_FAIL')
")
if echo "$result" | grep -q "SERIALIZER_OK"; then
    pass "Config serializer ($(echo "$result" | grep "SERIALIZER_OK" | cut -d: -f2))"
else
    fail "Config serializer: $result"
fi

# Test session manager
result=$(run_in_context "
from cli.session import SessionManager
from models_new import User
mgr = SessionManager()
user = User.query.filter_by(role='admin').first()
if user:
    sid = mgr.create_session(user, '127.0.0.1', 'test')
    mgr.end_session(sid)
    print('SESSION_OK')
else:
    print('SESSION_NO_USER')
")
if echo "$result" | grep -q "SESSION_OK"; then
    pass "Session manager (create/end session)"
else
    fail "Session manager: $result"
fi

# ============================================================================
# 4. SYSTEM LAYER
# ============================================================================

section "System Layer"

# Test dependency checker
result=$(run_in_context "
from system.checker import refresh_health
h = refresh_health()
if h.ready:
    print('DEPS_OK')
else:
    missing = h.to_dict().get('missing_required', [])
    print(f'DEPS_MISSING:{\"|\".join(missing)}')
")
if echo "$result" | grep -q "DEPS_OK"; then
    pass "System dependencies (all present)"
elif echo "$result" | grep -q "DEPS_MISSING:"; then
    missing=$(echo "$result" | grep "DEPS_MISSING:" | cut -d: -f2 | tr '|' ', ')
    fail "System dependencies missing: ${missing}"
else
    fail "Dependency checker: $result"
fi

# Test interface detection
result=$(run_in_context "
from system.interfaces import detect_all
ifaces = detect_all()
print(f'DETECT:{len(ifaces)}')
for i in ifaces:
    print(f'  {i.name} mac={i.mac} up={i.link_up}')
")
if echo "$result" | grep -q "DETECT:"; then
    count=$(echo "$result" | grep "DETECT:" | cut -d: -f2)
    pass "Interface detection (${count} interfaces)"
else
    fail "Interface detection: $result"
fi

# Test routing table
result=$(run_in_context "
from system.routing import get_routing_table, get_forwarding_status
routes = get_routing_table()
fwd = get_forwarding_status()
print(f'ROUTES:{len(routes)}:FWD={fwd}')
")
if echo "$result" | grep -q "ROUTES:"; then
    info=$(echo "$result" | grep "ROUTES:" | cut -d: -f2-)
    pass "Routing (${info})"
else
    fail "Routing: $result"
fi

# ============================================================================
# 5. WEB UI
# ============================================================================

section "Web UI"

# Check if the gateway service is running
if systemctl is-active --quiet warp-gateway 2>/dev/null; then
    pass "warp-gateway.service is running"

    # Test HTTP response
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/login 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        pass "Web UI responding (HTTP 200 on /login)"
    elif [ "$HTTP_CODE" = "302" ]; then
        pass "Web UI responding (HTTP 302 redirect)"
    else
        fail "Web UI not responding (HTTP ${HTTP_CODE})"
    fi
else
    skip "warp-gateway.service not running (start with: sudo systemctl start warp-gateway)"
fi

# ============================================================================
# 6. NETWORK SERVICES
# ============================================================================

section "Network Services"

# Check WireGuard
if command -v wg &>/dev/null; then
    pass "WireGuard tools installed"
else
    fail "WireGuard tools not installed"
fi

# Check dnsmasq
if command -v dnsmasq &>/dev/null; then
    pass "dnsmasq installed"
    if systemctl is-active --quiet dnsmasq 2>/dev/null; then
        pass "dnsmasq service running"
    else
        skip "dnsmasq not running (starts when DHCP is configured)"
    fi
else
    fail "dnsmasq not installed"
fi

# Check iptables
if command -v iptables &>/dev/null; then
    pass "iptables installed"
    RULE_COUNT=$(sudo iptables -L -n 2>/dev/null | grep -c "^[A-Z]" || echo "0")
    pass "iptables rules loaded (${RULE_COUNT} chains)"
else
    fail "iptables not installed"
fi

# Check diagnostic tools
for tool in ping traceroute mtr dig tcpdump iperf3; do
    if command -v "$tool" &>/dev/null; then
        pass "${tool} installed"
    else
        fail "${tool} not installed"
    fi
done

# ============================================================================
# SUMMARY
# ============================================================================

echo ""
echo "============================================================"
echo "  Test Results"
echo "============================================================"
echo ""
echo -e "  ${GREEN}Passed: ${PASS}${NC}"
echo -e "  ${RED}Failed: ${FAIL}${NC}"
echo -e "  ${YELLOW}Skipped: ${SKIP}${NC}"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "  ${RED}Some tests failed. Review the output above.${NC}"
    exit 1
else
    echo -e "  ${GREEN}All tests passed.${NC}"
    exit 0
fi
