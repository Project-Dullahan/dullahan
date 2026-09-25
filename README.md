# 🛡️ Dullahan

**An open-source, air-gapped, memory-safe endpoint defense suite designed for humanitarian aid workers, journalists, and civilians in contested or communications-denied environments.**

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

## 🎯 The Problem
In modern conflict zones, digital data leaks directly translate to physical, kinetic threats. Adversaries use automated scripts to scrape un-scrubbed metadata from photos, hijack local DNS to route aid workers to phishing clones, and use forensic extraction tools at checkpoints to find hidden browser history fragments. 

Traditional corporate security tools (like Windows Defender or cloud-based EDR) fail in these environments because they rely on continuous internet connectivity, emit radio frequency (RF) signatures, and send telemetry to the cloud.

## 💡 The Solution
**Dullahan** is a 100% offline-first, zero-telemetry defensive utility written in memory-safe Rust. It operates entirely on local artifacts, requiring no active network sockets. It automates the discipline that humans lose under stress, acting as a silent guardian against the most common, lethal digital mistakes in the field.

## 🚀 Core Features

### 1. Air-Gapped EXIF Metadata Sanitizer (`metadata.rs`)
- **The Threat:** Field workers uploading "proof of work" photos that silently contain raw GPS coordinates in the headers, leading to artillery/drone targeting.
- **The Fix:** A deterministic, zero-dependency byte-stream parser that reads local image files offline, instantly flagging or stripping `GPSLatitude`, `GPSLongitude`, and hardware identifiers before the file can be transmitted.

### 2. Sandbox Forensic Ledger Auditor (`forensics.rs`)
- **The Threat:** Physical checkpoint seizures where adversaries use forensic tools to read hidden SQLite database fragments (like Firefox `places.sqlite` or Chrome `History`), proving the user visited unauthorized aid or news portals.
- **The Fix:** A multi-platform parser that safely mirrors locked browser databases to temporary memory, bypassing OS write-locks to scan for lingering traces of high-risk domains, giving the user a 2-second "go/no-go" sanity check before a physical search.

### 3. Data Sovereignty & Baseline Verification (`main.rs`)
- **The Threat:** Local ISP or cellular tower hijacking (MITM) routing legitimate aid portals to cloned adversary servers.
- **The Fix:** A terminal-based interface that cross-references local environmental footprints against a cryptographically trusted `baseline.json` manifest, brought across borders via physical media (Sneakernet). If the observed IP or SSL certificate hash deviates, it triggers an immediate air-gap warning.

## 📦 Installation & Usage

Dullahan compiles to a single, standalone, dependency-free binary.

```bash
# Clone the repository
git clone https://github.com/Project-Dullahan/dullahan.git
cd dullahan

# Build the release binaries
cargo build --release

# Run the forensic history scanner (checks local browser sandboxes)
cargo run --release --bin audit_history

# Run the interactive TUI dashboard (requires a local correlation report)
./target/release/tui --input infra_correlation_report.json
