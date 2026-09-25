#!/usr/bin/env python3
import socket
import ssl
import hashlib
import json
import sys
from datetime import datetime, timezone

def get_domain_baseline(domain: str) -> dict:
    print(f"[*] Resolving {domain}...")
    try:
        # 1. Get IPs
        ips = list(set([addr[4][0] for addr in socket.getaddrinfo(domain, 443)]))
        
        # 2. Get SSL Certificate Hash
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert_sha256 = hashlib.sha256(cert_der).hexdigest()
                
        # 3. Mock ASN lookup (in production, use an offline IP-to-ASN database like MaxMind)
        asn = "AS-UNKNOWN (Verify manually)" 
        
        return {
            "domain": domain,
            "expected_ips": ips,
            "expected_asn": asn,
            "cert_sha256": cert_sha256
        }
    except Exception as e:
        print(f"[!] Failed to profile {domain}: {e}")
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_baseline.py <domain1> <domain2> ...")
        sys.exit(1)

    domains = sys.argv[1:]
    baseline = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "trusted_profiles": {}
    }

    print("[*] Starting secure-zone baseline generation...")
    for domain in domains:
        profile = get_domain_baseline(domain)
        if profile:
            baseline["trusted_profiles"][domain] = profile
            print(f"    [+] Profiled: {domain}")

    output_file = "baseline.json"
    with open(output_file, "w") as f:
        json.dump(baseline, f, indent=2)
    
    print(f"\n[✅] Success! Baseline saved to {output_file}")
    print("[!] IMPORTANT: Transfer this file to the field via encrypted, physical media only.")

if __name__ == "__main__":
    main()
