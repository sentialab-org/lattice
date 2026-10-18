#!/usr/bin/env bash
# Root daemons use protected system state and bundled WireGuard dependencies.
set -euo pipefail
umask 077
ARTIFACTS=""; TOKEN=""; ROLE=node; BOOTSTRAP=https://lattice.sentialab.org
while [[ $# -gt 0 ]]; do case "$1" in
    --node) ROLE=node; shift;;
    --master) ROLE=master; shift;;
    --relay) ROLE=relay; shift;;
    --token) TOKEN="${2:?--token requires the supervisor-issued activation token}"; shift 2;;
    --role) ROLE="$2"; shift 2;;
    --accept-terms) shift;;
    --artifact-dir) ARTIFACTS="$2"; shift 2;;
    --bootstrap-url) BOOTSTRAP="$2"; shift 2;;
    *) echo "Unknown installer option" >&2; exit 1;;
esac; done
[[ "$ROLE" == node || "$ROLE" == master || "$ROLE" == relay ]] || exit 1
VERIFY_ROLE="$ROLE"; [[ "$ROLE" != relay ]] || VERIFY_ROLE=node
SETUP_ROLE="$ROLE"; [[ "$ROLE" != relay ]] || SETUP_ROLE=node
[[ "$(id -u)" == 0 ]] || { echo "System installation requires sudo/root" >&2; exit 1; }
[[ -x "$ARTIFACTS/lattice-node" ]] || exit 1
"$ARTIFACTS/lattice-node" verify-bundle --artifact-dir "$ARTIFACTS" --role "$VERIFY_ROLE"
for f in wg wg-quick wireguard-go bash; do [[ -x "$ARTIFACTS/$f" ]] || { echo "Managed network dependency missing" >&2; exit 1; }; done
ROOT=""; if [[ "${LATTICE_INSTALL_TEST_MODE:-0}" == 1 ]]; then ROOT="${LATTICE_INSTALL_TEST_ROOT:?}"; [[ -d "$ROOT" && "$ROOT" != / ]] || exit 1; fi
STATE="$ROOT/Library/Application Support/Lattice"; BIN="$STATE/bin"; PLISTS="$ROOT/Library/LaunchDaemons"; SOCKET="$ROOT/var/run/lattice/node.sock"
mkdir -p "$STATE" "$BIN" "$PLISTS" "$(dirname "$SOCKET")"
chmod 700 "$STATE"; chmod 755 "$(dirname "$SOCKET")"
LEGACY=""
if [[ "${LATTICE_INSTALL_TEST_MODE:-0}" == 1 ]]; then LEGACY="${LATTICE_LEGACY_USER_STATE:-}";
elif [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
    USER_HOME="$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory | cut -d ' ' -f 2-)"
    LEGACY="$USER_HOME/Library/Application Support/Lattice"
    USER_ID="$(id -u "$SUDO_USER")"
    launchctl bootout "gui/$USER_ID/com.lattice.node" 2>/dev/null || true
    launchctl bootout "gui/$USER_ID/com.lattice.master" 2>/dev/null || true
fi
if [[ -n "$LEGACY" && -d "$LEGACY" && ! -f "$STATE/identity.json" ]]; then
    [[ -z "$(find "$LEGACY" -type l -print -quit)" ]] || { echo "Legacy state contains symbolic links; migration stopped" >&2; exit 1; }
    cp -Rp "$LEGACY/." "$STATE/"
    if [[ -f "$LEGACY/identity.json" ]]; then cmp -s "$LEGACY/identity.json" "$STATE/identity.json" || exit 1; fi
    echo "Legacy state copied; original retained for recovery."
fi
BACKUP="$(mktemp -d "$BIN/.rollback.XXXXXXXX")"; STAGE="$(mktemp -d "$BIN/.install.XXXXXXXX")"
cp -R "$ARTIFACTS/." "$STAGE/"
for role in node master; do
    [[ ! -f "$PLISTS/com.lattice.$role.plist" ]] || cp "$PLISTS/com.lattice.$role.plist" "$BACKUP/$role.plist"
    if launchctl print "system/com.lattice.$role" >/dev/null 2>&1; then touch "$BACKUP/$role.loaded"; fi
done
rollback() {
    local code=$?
    if [[ $code -ne 0 ]]; then
        set +e
        launchctl bootout system/com.lattice.node 2>/dev/null || true
        launchctl bootout system/com.lattice.master 2>/dev/null || true
        if [[ "${LATTICE_INSTALL_TEST_MODE:-0}" != 1 && -x "$BIN/current/wg-quick" && -f "$STATE/wg-lattice.conf" ]]; then
            "$BIN/current/wg-quick" down "$STATE/wg-lattice.conf" >/dev/null 2>&1 || true
        fi
        [[ ! -d "$BIN/current" ]] || mv "$BIN/current" "$BACKUP/failed"
        [[ ! -d "$BACKUP/current" ]] || mv "$BACKUP/current" "$BIN/current"
        for role in node master; do
            if [[ -f "$BACKUP/$role.plist" ]]; then
                cp "$BACKUP/$role.plist" "$PLISTS/com.lattice.$role.plist"
                [[ ! -f "$BACKUP/$role.loaded" ]] || launchctl bootstrap system "$PLISTS/com.lattice.$role.plist"
            else rm -f "$PLISTS/com.lattice.$role.plist"; fi
        done
        echo "Lattice installed: no — setup failed" >&2
        echo "Setup failed; prior binaries and daemons restored. State retained." >&2
    fi
    [[ ! -d "$STAGE" ]] || rm -rf "$STAGE"
    exit "$code"
}
trap rollback EXIT
launchctl bootout system/com.lattice.node 2>/dev/null || true
launchctl bootout system/com.lattice.master 2>/dev/null || true
[[ ! -f "$PLISTS/com.lattice.master.plist" ]] || mv "$PLISTS/com.lattice.master.plist" "$BACKUP/retired-master.plist"
# A stopped daemon can leave its socket behind; only a newly bound socket is ready.
[[ ! -S "$SOCKET" ]] || rm -f "$SOCKET"
[[ ! -d "$BIN/current" ]] || mv "$BIN/current" "$BACKUP/current"
mv "$STAGE" "$BIN/current"
chmod 755 "$BIN/current/"lattice-* "$BIN/current/lattice" "$BIN/current/wg" "$BIN/current/wg-quick" "$BIN/current/wireguard-go" "$BIN/current/bash"
xml() { local value="$1"; value="${value//&/\&amp;}"; value="${value//</\&lt;}"; value="${value//>/\&gt;}"; value="${value//\"/\&quot;}"; printf '%s' "$value"; }
write_plist() {
    local role="$1" binary="$2" data="$3"
    cat > "$PLISTS/com.lattice.$role.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.lattice.$role</string>
<key>UserName</key><string>root</string>
<key>ProgramArguments</key><array><string>$(xml "$BIN/current/$binary")</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>5</integer><key>Umask</key><integer>63</integer>
<key>EnvironmentVariables</key><dict>
<key>PATH</key><string>$(xml "$BIN/current"):/usr/bin:/bin:/usr/sbin:/sbin</string>
<key>LATTICE_CONFIG</key><string>$(xml "$STATE/node.json")</string>
<key>LATTICE_SOCKET</key><string>$(xml "$SOCKET")</string>
<key>LATTICE_OWNER_UID</key><string>$(id -u "${SUDO_USER:-root}")</string>
<key>LATTICE_IPC_GID</key><string>$(id -g "${SUDO_USER:-root}")</string>
<key>LATTICE_MASTER_DATA</key><string>$(xml "$STATE/master")</string>
<key>LATTICE_WG_QUICK</key><string>$(xml "$BIN/current/wg-quick")</string>
<key>WG_QUICK_USERSPACE_IMPLEMENTATION</key><string>$(xml "$BIN/current/wireguard-go")</string>
<key>LATTICE_CONTROL_DATA</key><string>$(xml "$data")</string>
</dict>
<key>StandardOutPath</key><string>$(xml "$STATE/$role.log")</string>
<key>StandardErrorPath</key><string>$(xml "$STATE/$role-error.log")</string>
</dict></plist>
PLIST
    plutil -lint "$PLISTS/com.lattice.$role.plist"
    chmod 644 "$PLISTS/com.lattice.$role.plist"
    chown root:wheel "$PLISTS/com.lattice.$role.plist"
}
chown -R root:wheel "$STATE"
write_plist node lattice-node "$STATE/master"
launchctl bootstrap system "$PLISTS/com.lattice.node.plist"
if [[ "${LATTICE_INSTALL_TEST_MODE:-0}" != 1 ]]; then
    for ((i=0;i<60;i++)); do [[ ! -S "$SOCKET" ]] || break; sleep 1; done
    [[ -S "$SOCKET" ]] || { echo "Node IPC did not start" >&2; exit 1; }
fi
export LATTICE_CONFIG="$STATE/node.json" LATTICE_SOCKET="$SOCKET" LATTICE_MASTER_DATA="$STATE/master" LATTICE_WG_QUICK="$BIN/current/wg-quick"
export PATH="$BIN/current:/usr/bin:/bin:/usr/sbin:/sbin"
# Harness tools remain first only in the explicit disposable-path test mode.
if [[ "${LATTICE_INSTALL_TEST_MODE:-0}" == 1 ]]; then export PATH="${LATTICE_TEST_SHIMS:?}:$PATH"; fi
# An earlier installation or a rolled-back setup can leave a live overlay interface
# without its configuration file; wg-quick cannot stop that state by itself.
if [[ "${LATTICE_INSTALL_TEST_MODE:-0}" != 1 && -f /var/run/wireguard/wg-lattice.name ]]; then
    STALE="$(cat /var/run/wireguard/wg-lattice.name)"
    if [[ "$STALE" =~ ^utun[0-9]+$ ]]; then
        if ! "$BIN/current/wg" show "$STALE" >/dev/null 2>&1; then
            rm -f /var/run/wireguard/wg-lattice.name
        elif [[ ! -f "$STATE/wg-lattice.conf" ]]; then
            ifconfig "$STALE" down 2>/dev/null || true
            pkill -f "wireguard-go.*$STALE" 2>/dev/null || true
            rm -f /var/run/wireguard/wg-lattice.name
        fi
    fi
fi
if [[ -n "$TOKEN" && "$SETUP_ROLE" != master ]]; then
    echo "Note: activation tokens apply to --master installs; relay authorization is granted by the supervisor after the node joins." >&2
fi
set +e
SETUP_ARGS=(--role "$SETUP_ROLE" --bootstrap-url "$BOOTSTRAP" --timeout-secs 120)
if [[ -n "$TOKEN" && "$SETUP_ROLE" == master ]]; then
    printf '%s' "$TOKEN" | "$BIN/current/lattice-node" setup "${SETUP_ARGS[@]}" --master-token-stdin
else
    "$BIN/current/lattice-node" setup "${SETUP_ARGS[@]}"
fi
RESULT=$?
set -e
[[ $RESULT == 0 || $RESULT == 2 ]] || exit 1

RELAY_STATE=""
if [[ "$ROLE" == relay ]]; then
    set +e
    RELAY_OUT="$("$BIN/current/lattice-node" module enable --kind relay 2>&1)"
    RELAY_CODE=$?
    set -e
    if [[ $RELAY_CODE == 0 ]]; then RELAY_STATE="enabled"; else RELAY_STATE="pending supervisor authorization"; fi
fi
if [[ "${LATTICE_INSTALL_TEST_MODE:-0}" != 1 ]]; then
    mkdir -p /usr/local/bin
    ln -sf "$BIN/current/lattice" /usr/local/bin/lattice
fi
STATUS_JSON="$("$BIN/current/lattice-node" setup --wait --json --timeout-secs 3 2>/dev/null | tail -1 || true)"
STAGE="$(printf '%s' "$STATUS_JSON" | sed -n 's/.*"stage":"\([a-z_]*\)".*/\1/p')"
VIRTUAL_IP="$(printf '%s' "$STATUS_JSON" | sed -n 's/.*"virtual_ipv4":"\([^"]*\)".*/\1/p')"
NETWORK_READY="$(printf '%s' "$STATUS_JSON" | sed -n 's/.*"network_ready":\(true\|false\).*/\1/p')"

trap - EXIT
echo
echo "Lattice installed: yes"
case "$STAGE" in
    ready) echo "Network: connected — ready for workloads" ;;
    waiting_for_master) echo "Network: connected — workload master selection pending" ;;
    *) echo "Network: setup stage ${STAGE:-unknown}; the daemon keeps retrying" ;;
esac
[[ -z "$VIRTUAL_IP" ]] || echo "Virtual IP: $VIRTUAL_IP"
case "$ROLE" in
    master) echo "Supervisor: confirmed — role master" ;;
    relay) echo "Supervisor: joined — role relay (${RELAY_STATE:-pending})" ;;
    *) echo "Supervisor: confirmed — role node" ;;
esac
[[ "$NETWORK_READY" != false ]] || echo "Network state: not ready yet; the daemon keeps retrying"
echo "Service: com.lattice.node (launchd). CLI: sudo lattice list. Recovery snapshot: $BACKUP"
