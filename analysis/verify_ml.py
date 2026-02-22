import requests
import json

urls = [
    "https://google.com/",
    "http://verify-paypal-account-support.com/update",
    "http://xn--80ak6aa92e.com/"
]

results = []
for url in urls:
    try:
        response = requests.post(
            "http://localhost:8000/analyze",
            json={"url": url, "scan_type": "full"},
            timeout=10
        )
        results.append({
            "url": url,
            "status": response.status_code,
            "data": response.json()
        })
    except Exception as e:
        results.append({"url": url, "error": str(e)})

print(json.dumps(results, indent=2))
