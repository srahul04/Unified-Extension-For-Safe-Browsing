import requests
import json
import time

def test_analyze(url, scan_type="full"):
    print(f"\nTesting URL: {url}")
    try:
        response = requests.post("http://localhost:8000/analyze", json={"url": url, "scan_type": scan_type})
        if response.status_code == 200:
            data = response.json()
            print(f"Status: {data['status_label']} (Score: {data['risk_score']})")
            print(f"SRI Score: {data['features'].get('sri_score')}%")
            print(f"CSP Strength: {data['features'].get('csp_strength_score')}")
            print(f"Extra Security: {json.dumps(data.get('extra_security'), indent=2)}")
        else:
            print(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Failed to connect: {e}")

if __name__ == "__main__":
    print("Waiting for server to be ready...")
    time.sleep(2)
    # Test a site with strong security (GitHub)
    test_analyze("https://github.com/login")
    
    # Test a site likely missing SRI/CSP
    test_analyze("https://example.com")
