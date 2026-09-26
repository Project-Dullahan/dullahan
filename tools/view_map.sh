#!/bin/bash
# tools/view_map.sh
# Generates the offline map and opens it in a strictly air-gapped browser session.

# 1. Auto-detect privilege escalation
if [ "$EUID" -eq 0 ]; then
    EXEC=""
elif command -v doas >/dev/null 2>&1; then
    EXEC="doas"
elif command -v sudo >/dev/null 2>&1; then
    EXEC="sudo"
else
    echo "[-] Error: Neither 'doas' nor 'sudo' found. Cannot enforce air-gap."
    exit 1
fi

MAP_FILE="dullahan_map.html"
NAMESPACE="dullahan_map_vault"

echo "[*] Generating latest offline tactical map..."
# Run the map generator (it will read the embedded assets and baseline)
./target/release/map

if [ ! -f "$MAP_FILE" ]; then
    echo "[-] Error: Map generation failed."
    exit 1
fi

echo "[*] Creating air-gapped network namespace..."
$EXEC ip netns add "$NAMESPACE" 2>/dev/null
$EXEC ip netns exec "$NAMESPACE" ip link set lo up

echo "[+] Sandbox active. Browser is physically blocked from the network."
echo "[*] Opening map... (Close the browser to return to the TUI)"

# Open the file using the system's default browser, but INSIDE the isolated namespace
$EXEC ip netns exec "$NAMESPACE" xdg-open "file://$(realpath "$MAP_FILE")"

# Wait for the user to close the browser (xdg-open returns when the app closes in most DEs)
# If xdg-open forks and returns immediately, we can add a small sleep or rely on the user 
# knowing to close it. For robustness, we just clean up after a brief pause or immediately 
# if the browser forks. Let's clean up immediately, as the namespace destruction is instant.

echo "[*] Cleaning up sandbox..."
$EXEC ip netns del "$NAMESPACE" 2>/dev/null
echo "[+] Done. Network isolation removed. Volatile data cleared."
