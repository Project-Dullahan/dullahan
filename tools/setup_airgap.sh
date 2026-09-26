#!/bin/bash
# tools/setup_airgap.sh
# Sets up a kernel-level network block for the Dullahan application.

# 1. Auto-detect privilege escalation method
if [ "$EUID" -eq 0 ]; then
    EXEC=""
elif command -v doas >/dev/null 2>&1; then
    EXEC="doas"
elif command -v sudo >/dev/null 2>&1; then
    EXEC="sudo"
else
    echo "[-] Error: Neither 'doas' nor 'sudo' found, and not running as root."
    echo "    Please install one, or run this script as root."
    exit 1
fi

echo "[*] Setting up kernel-level air-gap for Dullahan..."

# 2. Create restricted, non-login system user
if id "dullahan_user" &>/dev/null; then
    echo "[*] User 'dullahan_user' already exists."
else
    echo "[*] Creating restricted user 'dullahan_user'..."
    $EXEC useradd -r -s /bin/false dullahan_user
fi

# 3. Apply iptables egress block (idempotent: won't add duplicate rules)
if $EXEC iptables -C OUTPUT -m owner --uid-owner dullahan_user -j DROP 2>/dev/null; then
    echo "[*] Firewall rule already exists."
else
    echo "[*] Adding iptables egress block for 'dullahan_user'..."
    $EXEC iptables -I OUTPUT 1 -m owner --uid-owner dullahan_user -j DROP
    echo "[+] Firewall rule applied successfully."
fi

echo "[+] Setup complete."
echo "[!] To run Dullahan safely, use: ./tools/run_secure.sh"
