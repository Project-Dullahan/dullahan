# tools/sync_baselines.py (Refined)
import json, socket, ssl, hashlib, sys
from datetime import datetime, timezone

def generate_all_baselines(target_file="targets.txt", output_file="baseline.json"):
    try:
        with open(target_file, "r") as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[-] Error: {target_file} not found.")
        return

    manifests = {"generated_at": datetime.now(timezone.utc).isoformat(), "trusted_profiles": {}}
    
    for domain in domains:
        print(f"[*] Automating baseline collection for: {domain}")
        try:
            ips = list(set([info[4][0] for info in socket.getaddrinfo(domain, 443)]))
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_sha256 = hashlib.sha256(cert_der).hexdigest()
            
            manifests["trusted_profiles"][domain] = {
                "domain": domain,
                "expected_ips": ips,
                "expected_asn": "AUTO-DETECTED", # Placeholder for future MaxMind integration
                "expected_cert_sha256": cert_sha256
            }
        except Exception as e:
            print(f" [!] Skipped {domain}: {e}")

    with open(output_file, "w") as f:
        json.dump(manifests, f, indent=2)
    print(f"[+] Automation Complete! Manifest saved to {output_file}")

if __name__ == "__main__":
    generate_all_baselines()
