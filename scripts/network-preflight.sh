#!/bin/sh
# Lattice overlay network preflight check (read-only, makes no system changes).
# Usage: sh scripts/network-preflight.sh [gateway_endpoint]
# Env overrides: LATTICE_NETWORK_CIDR, LATTICE_NETWORK_GATEWAY_ENDPOINT,
#   LATTICE_NETWORK_INTERFACE
set -u

CIDR="${LATTICE_NETWORK_CIDR:-10.77.0.0/16}"
GATEWAY_ENDPOINT="${1:-${LATTICE_NETWORK_GATEWAY_ENDPOINT:-}}"
IFACE="${LATTICE_NETWORK_INTERFACE:-lattice0}"
FAIL=0
WARN=0

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
warn() { echo "WARN: $1"; WARN=$((WARN + 1)); }
info() { echo "INFO: $1"; }

info "Lattice network preflight"
info "overlay_cidr=$CIDR interface=$IFACE gateway_endpoint=${GATEWAY_ENDPOINT:-unset}"

if command -v wg >/dev/null 2>&1; then
  pass "wireguard tools present: $(wg --version 2>&1 | head -n 1)"
else
  fail "wireguard tools missing (wg not found)"
fi

if command -v ip >/dev/null 2>&1; then
  pass "iproute2 present"
else
  warn "ip command missing (non-Linux or minimal PATH)"
fi

if ip link show "$IFACE" >/dev/null 2>&1; then
  warn "interface $IFACE already exists"
  ip -o addr show dev "$IFACE" 2>/dev/null || true
else
  pass "interface $IFACE absent (clean slate)"
fi

if wg show 2>/dev/null | grep -q "interface:"; then
  warn "existing WireGuard interfaces detected"
  wg show interfaces 2>/dev/null || true
else
  pass "no active WireGuard interfaces"
fi

if command -v tailscale >/dev/null 2>&1 && tailscale status >/dev/null 2>&1; then
  warn "tailscale active, verify no 100.64.0.0/10 or overlay overlap"
  tailscale status 2>/dev/null | head -n 5 || true
else
  pass "no active tailscale detected"
fi

for cidr in "10.77.0.0/16" "10.240.0.0/16"; do
  if command -v ip >/dev/null 2>&1 && ip route get "${cidr%%/*}" >/dev/null 2>&1; then
    info "route lookup for $cidr: $(ip route get "${cidr%%/*}" 2>/dev/null | head -n 1)"
  fi
done

if command -v ip >/dev/null 2>&1; then
  if ip route show | grep -q "10.77.0.0/16"; then
    fail "conflicting 10.77.0.0/16 route present"
    ip route show | grep "10.77" || true
  else
    pass "no conflicting 10.77.0.0/16 route"
  fi
fi

if [ -r /proc/sys/net/ipv4/ip_forward ]; then
  val="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)"
  if [ "$val" = "1" ]; then
    pass "ipv4 forwarding enabled (gateway hosts require 1)"
  else
    warn "ipv4 forwarding disabled (value=$val, required on gateway)"
  fi
else
  warn "cannot read ip_forward (non-Linux or restricted)"
fi

if [ -z "$GATEWAY_ENDPOINT" ]; then
  warn "gateway endpoint unset, skipping UDP reachability probe"
else
  host="${GATEWAY_ENDPOINT%:*}"
  port="${GATEWAY_ENDPOINT##*:}"
  if command -v nc >/dev/null 2>&1; then
    if nc -u -z -w 3 "$host" "$port" >/dev/null 2>&1; then
      warn "UDP send succeeded to $GATEWAY_ENDPOINT (send-only, handshake still required)"
    else
      fail "UDP unreachable: $GATEWAY_ENDPOINT (SSH/HTTPS success does not prove UDP ingress)"
    fi
  else
    warn "nc missing, cannot probe UDP $GATEWAY_ENDPOINT"
  fi
fi

echo "---"
echo "failures=$FAIL warnings=$WARN"
if [ "$FAIL" -gt 0 ]; then
  echo "RESULT: BLOCKED, resolve FAIL items before gateway or P2P changes"
  exit 1
fi
echo "RESULT: READY (warnings advisory)"
