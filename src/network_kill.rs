// src/network_kill.rs
use std::process::Command;
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct NetworkStatus {
    pub interfaces_down: Vec<String>,
    pub rfkill_blocked: bool,
    pub firewall_locked: bool,
    pub is_airgapped: bool,
    pub error: Option<String>,
}

/// Physically block all wireless radios and bring down network interfaces.
/// Requires root/sudo privileges.
pub fn enforce_airgap() -> NetworkStatus {
    let mut status = NetworkStatus {
        interfaces_down: Vec::new(),
        rfkill_blocked: false,
        firewall_locked: false,
        is_airgapped: false,
        error: None,
    };

    // Check if we have root
    if !is_root() {
        status.error = Some("Requires root privileges. Run with sudo.".to_string());
        return status;
    }

    // 1. Block all wireless radios (WiFi, Bluetooth, etc.)
    match Command::new("rfkill").args(["block", "all"]).output() {
        Ok(output) if output.status.success() => status.rfkill_blocked = true,
        Ok(_) => status.error = Some("rfkill block failed".to_string()),
        Err(e) => status.error = Some(format!("rfkill not available: {}", e)),
    }

    // 2. Bring down all network interfaces except loopback
    if let Ok(output) = Command::new("ip").args(["-o", "link", "show"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let iface = parts[1].trim_end_matches(':');
                if iface != "lo" && !iface.is_empty() {
                    if Command::new("ip")
                        .args(["link", "set", iface, "down"])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                    {
                        status.interfaces_down.push(iface.to_string());
                    }
                }
            }
        }
    }

    // 3. Failsafe: Drop ALL outbound traffic via iptables
    let fw_success = Command::new("iptables")
        .args(["-I", "OUTPUT", "1", "-j", "DROP"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    status.firewall_locked = fw_success;

    // 4. Verify the air-gap
    status.is_airgapped = status.rfkill_blocked && !status.interfaces_down.is_empty();

    status
}

/// Restore network access (for cleanup)
pub fn restore_network() {
    if !is_root() {
        return;
    }

    let _ = Command::new("rfkill").args(["unblock", "all"]).output();

    let _ = Command::new("iptables").args(["-D", "OUTPUT", "-j", "DROP"]).output();

    if let Ok(output) = Command::new("ip").args(["-o", "link", "show"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let iface = parts[1].trim_end_matches(':');
                if iface != "lo" && !iface.is_empty() {
                    let _ = Command::new("ip")
                        .args(["link", "set", iface, "up"])
                        .output();
                }
            }
        }
    }
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
