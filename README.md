# 🛡️ Dullahan

**An open-source, offline-first digital security toolkit for humanitarian aid workers, journalists, and civilians in contested or communications-denied environments.**
**IN-PROGRESS**

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

## The Problem
In contested environments, ordinary digital habits create real physical risk: unscrubbed photo metadata reveals exact locations, hijacked local DNS can route people to cloned phishing infrastructure, and forensic extraction at checkpoints can surface browsing history a person believed was deleted.

Most consumer security software assumes constant internet connectivity and phones home for updates and telemetry — a reasonable tradeoff in an ordinary environment, but the wrong one for someone trying to minimize their network footprint entirely.

## The Solution
Dullahan is a set of offline-first tools, written in Rust, that make zero network requests during normal operation. Each tool works from local files or data prepared in advance, so using it adds no new network exposure.

## Core Features

### 1. EXIF Metadata Auditor (`audit.rs`)
Detects GPS coordinates and device-identifying metadata embedded in photo files before they're shared. Currently a detector: it flags unsafe files and recommends stripping them with `exiftool -all=`. (Built-in stripping is a planned next step, not yet implemented.)

### 2. Offline Browser History Auditor (`audit_history.rs`)
Scans local browser history databases (Firefox, Chrome, Chromium, Brave, including Flatpak/Snap installs) against a threat-intelligence list and a heuristic risk score, entirely offline. Copies databases to a temp file first to avoid lock conflicts with a running browser, and fails secure — it will never report "clean" if it couldn't actually check.

### 3. Network Baseline Verification (`generate_baseline.py` + in-progress verifier)
`generate_baseline.py` records a trusted manifest of a domain's expected IP addresses and TLS certificate hash, meant to be carried in ahead of time. **Status: manifest generation is implemented; the runtime checker that compares a live connection against that manifest and warns on mismatch is still in progress.**

### 4. Passive Traffic Analysis (`har_analyzer.rs`)
Analyzes browser-exported HAR files entirely offline — no live requests to the site being analyzed. Reports data volume per domain, flags unusually high tracker density, and flags basic fingerprinting-script indicators.

### 5. Infrastructure Correlation (`infra_correlator.rs`)
Given a list of domains, finds infrastructure they share — IP addresses, TLS certificates, tracking IDs, HTML structure — as a way to identify domains that may be operated by the same entity.

## Installation & Usage

Dullahan compiles to standalone binaries with no runtime services required. It depends on standard Rust crates at build time (see `Cargo.toml`).

\```bash
git clone https://github.com/Project-Dullahan/dullahan.git
cd dullahan
cargo build --release

# Offline browser history audit
cargo run --release --bin audit_history

# Interactive dashboard (requires a local correlation report)
./target/release/tui --input infra_correlation_report.json
\
