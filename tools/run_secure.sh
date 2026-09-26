#!/bin/bash
# tools/run_secure.sh
# Executes Dullahan under the restricted, internet-blocked user.

# 1. Auto-detect privilege escalation method
if [ "$EUID" -eq 0 ]; then
    EXEC=""
elif command -v doas >/dev/null 2>&1; then
    EXEC="doas"
elif command -v sudo >/dev/null 2>&1; then
    EXEC="sudo"
else
    echo "[-] Error: Neither 'doas' nor 'sudo' found."
    exit 1
fi

# 2. Verify the user and rule exist
if ! id "dullahan_user" &>/dev/null; then
    echo "[-] Error: 'dullahan_user' not found. Run './tools/setup_airgap.sh' first."
    exit 1
fi

# 3. Execute the compiled binary as the restricted user
echo "[*] Launching Dullahan in air-gapped mode (UID: dullahan_user)..."
echo "[*] All outbound network traffic for this process is blocked by the kernel."
$EXEC -u dullahan_user ./target/release/dullahan "$@"
