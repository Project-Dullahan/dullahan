#!/usr/bin/env python3
import json
import socket
import ssl
import hashlib
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

def get_ip_geolocation(ip: str):
    """Fetches lat/lon for an IP using a free, no-auth API (Safe-zone only)"""
    try:
        url = f"https://ipapi.co/{ip}/json/"
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
            return {
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "country": data.get("country_name", "Unknown"),
                "asn": data.get("asn", "Unknown")
            }
    except Exception:
        return {"latitude": None, "longitude": None, "country": "Unknown", "asn": "Unknown"}

def generate_all_baselines(target_file="targets.txt", output_file="baseline.json"):
    try:
        with open(target_file, "r") as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[-] Error: {target_file} not found.")
        return

    manifests = {"generated_at": datetime.now(timezone.utc).isoformat(), "trusted_profiles": {}}
    
    for domain in domains:
        print(f"[*] Profiling: {domain}")
        try:
            # 1. Resolve IP
            ips = list(set([info[4][0] for info in socket.getaddrinfo(domain, 443)]))
            
            # 2. Get Cert Hash
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_sha256 = hashlib.sha256(cert_der).hexdigest()
            
            # 3. Get Geolocation for the primary IP
            primary_ip = ips[0]
            geo_data = get_ip_geolocation(primary_ip)
            
            manifests["trusted_profiles"][domain] = {
                "domain": domain,
                "expected_ips": ips,
                "expected_cert_sha256": cert_sha256,
                "resolved_infrastructure": [{
                    "ip": primary_ip,
                    "asn": geo_data["asn"],
                    "country": geo_data["country"],
                    "coordinates": {
                        "latitude": geo_data["latitude"],
                        "longitude": geo_data["longitude"]
                    } if geo_data["latitude"] else None
                }]
            }
            print(f"    [+] Mapped {primary_ip} to {geo_data['country']}")
            
        except Exception as e:
            print(f" [!] Skipped {domain}: {e}")

    with open(output_file, "w") as f:
        json.dump(manifests, f, indent=2)
    print(f"[+] Automation Complete! Manifest saved to {output_file}")

if __name__ == "__main__":
    generate_all_baselines()
