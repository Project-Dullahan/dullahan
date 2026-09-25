
#!/usr/bin/env python3
import json
import sys
from datetime import datetime, timezone

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_threat_intel.py <domain1> <domain2> ...")
        print("Example: python3 generate_threat_intel.py bad-actor.com phishing-site.net")
        sys.exit(1)

    domains = [d.lower().strip() for d in sys.argv[1:]]
    
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "blocked_domains": domains
    }

    output_file = "threat_intel.json"
    with open(output_file, "w") as f:
        json.dump(payload, f, indent=2)
    
    print(f"[✅] Success! Threat intelligence manifest saved to {output_file}")
    print("[!] IMPORTANT: Transfer this file to the field via encrypted, physical media only.")
    print(f"    Target path: ~/.config/dullahan/threat_intel.json")

if __name__ == "__main__":
    main()
