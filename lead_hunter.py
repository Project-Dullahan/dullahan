import sys
import re
import requests

def extract_leads(url):
    print("[DULLAHAN] Initiating contact information extraction...")
    print(f"Target: {url}\n")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Dullahan/0.1 Security Audit"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            print(f"Error: Target returned HTTP status {response.status_code}")
            return
            
        html_content = response.text
        
        phone_pattern = r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        phones = list(set(re.findall(phone_pattern, html_content)))
        
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = list(set(re.findall(email_pattern, html_content)))
        
        print("=== EXTRACTION RESULTS ===")
        if not phones and not emails:
            print("[INFO] No standard phone numbers or email addresses found in plaintext.")
        else:
            print(f"[INFO] Found {len(phones)} phone number(s) and {len(emails)} email address(es):\n")
            for mail in emails:
                print(f"  - EMAIL: {mail}")
            for phone in phones:
                print(f"  - PHONE: {phone}")
        print("==========================")
        
    except Exception as e:
        print(f"Error: Request failed. ({e})")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 lead_hunter.py <url>")
        sys.exit(1)
    extract_leads(sys.argv[1])
