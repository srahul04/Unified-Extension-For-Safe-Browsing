import requests
import json

def verify_ecc():
    url = "https://google.com"
    print(f"Testing ECC Detection and Signing for: {url}")
    
    # Test the Express Orchestrator (which calls the Python service)
    try:
        response = requests.post("http://localhost:5000/api/scan", json={"url": url, "scan_type": "full"})
        data = response.json()
        
        print("\n--- Scan Results ---")
        print(f"URL: {data.get('url')}")
        print(f"Risk Score: {data.get('ml_results', {}).get('risk_score')}")
        
        print("\n--- Cryptography (ECC) ---")
        crypto = data.get("cryptography", {})
        print(f"Algorithm: {crypto.get('algorithm')}")
        print(f"Strength: {crypto.get('strength')}")
        
        print("\n--- Integrity (Digital Signature) ---")
        integrity = data.get("integrity", {})
        print(f"Algorithm: {integrity.get('algorithm')}")
        print(f"Signature (truncated): {integrity.get('signature', '')[:20]}...")
        print(f"Public Key: {integrity.get('publicKey')}")
        
    except Exception as e:
        print(f"Verification Failed: {e}")

if __name__ == "__main__":
    verify_ecc()
