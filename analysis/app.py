from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import re
from urllib.parse import urlparse, urljoin
import math
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import pandas as pd
import uvicorn
import requests
from bs4 import BeautifulSoup
import time

app = FastAPI(title="WebGuard AI-ML Analysis Service v3.0")

# Advanced ML Model definition
class SecurityAnalyzer:
    def __init__(self):
        self.model = self._train_initial_model()
        self.feature_names = [
            "length", "entropy", "subdomain_count", "has_ip", 
            "special_chars", "digit_ratio", "is_https", "suspicious_patterns",
            "hidden_iframes", "suspicious_scripts", "privacy_score",
            "xss_patterns", "sqli_patterns", "redirect_loops",
            "missing_csp", "missing_hsts", "missing_xframe"
        ]

    def _train_initial_model(self):
        # Features: [length, entropy, subdomains, has_ip, special, digit_ratio, https, patterns, iframes, scripts, privacy, xss, sqli, redirects, csp, hsts, xframe]
        data = [
            [20, 3.2, 1, 0, 2, 0.05, 1, 0, 0, 0, 90, 0, 0, 0, 0, 0, 0],  # Safe
            [80, 4.5, 4, 1, 10, 0.25, 0, 1, 2, 1, 10, 1, 1, 1, 1, 1, 1], # Critical
            [15, 2.5, 1, 0, 1, 0.0, 1, 0, 0, 0, 85, 0, 0, 0, 0, 0, 0],   # Safe
            [120, 5.1, 5, 0, 15, 0.30, 0, 1, 1, 3, 5, 2, 0, 2, 1, 0, 1],  # Dangerous
            [45, 3.8, 2, 0, 5, 0.10, 1, 0, 0, 0, 70, 0, 1, 0, 0, 1, 0],   # Vulnerable
            [100, 4.8, 3, 1, 12, 0.20, 0, 1, 3, 2, 0, 1, 2, 1, 1, 1, 1],  # High Risk
        ]
        labels = [0, 1, 0, 1, 0, 1] 
        X = np.array(data)
        y = np.array(labels)
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X, y)
        return clf

    def calculate_entropy(self, text: str) -> float:
        if not text: return 0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return - sum([p * math.log(p) / math.log(2.0) for p in prob]) if prob else 0

    async def analyze_security_headers(self, response: requests.Response):
        headers = response.headers
        audit = {
            "missing_csp": 1 if 'Content-Security-Policy' not in headers else 0,
            "missing_hsts": 1 if 'Strict-Transport-Security' not in headers else 0,
            "missing_xframe": 1 if 'X-Frame-Options' not in headers else 0
        }
        return audit

    async def fetch_and_analyze_content(self, url: str, full_audit: bool = True):
        vulnerabilities = {
            "hidden_iframes": 0, "suspicious_scripts": 0, "xss_patterns": 0,
            "sqli_patterns": 0, "redirect_loops": 0,
            "missing_csp": 0, "missing_hsts": 0, "missing_xframe": 0
        }
        privacy_signals = {"has_policy": False, "score": 0}
        
        try:
            # Quick checks always done on URL
            if re.search(r'(<script|alert\(|onerror=|<img|javascript:)', url, re.I):
                vulnerabilities["xss_patterns"] += 1
            if re.search(r'(UNION SELECT|--|OR 1=1|DROP TABLE|INSERT INTO)', url, re.I):
                vulnerabilities["sqli_patterns"] += 1

            headers = {'User-Agent': 'WebGuard-Security-Audit/3.2'}
            # If not full audit, we do a HEAD request or limited GET
            if not full_audit:
                response = requests.head(url, timeout=3, headers=headers, allow_redirects=True)
                vulnerabilities.update(await self.analyze_security_headers(response))
                return vulnerabilities, privacy_signals

            response = requests.get(url, timeout=5, headers=headers, allow_redirects=True)
            vulnerabilities.update(await self.analyze_security_headers(response))
            
            if len(response.history) > 3:
                vulnerabilities["redirect_loops"] += 1

            soup = BeautifulSoup(response.text, 'lxml')
            
            # Deep content checks
            inputs = soup.find_all(['input', 'textarea'])
            vulnerabilities["xss_patterns"] += sum(1 for inp in inputs if inp.get('onmouseover') or inp.get('onclick'))

            if soup.find('meta', attrs={'http-equiv': 'refresh'}):
                vulnerabilities["redirect_loops"] += 1

            iframes = soup.find_all('iframe')
            for iframe in iframes:
                style = iframe.get('style', '').lower()
                if 'display:none' in style or 'visibility:hidden' in style or (iframe.get('width') == '0' or iframe.get('height') == '0'):
                    vulnerabilities["hidden_iframes"] += 1
            
            scripts = soup.find_all('script')
            suspicious_keywords = ['eval(', 'unescape(', 'document.write(unescape', 'base64', 'String.fromCharCode']
            for script in scripts:
                content = script.string if script.string else ""
                if any(kw in content for kw in suspicious_keywords):
                    vulnerabilities["suspicious_scripts"] += 1
            
            # Policy Auditor
            policy_links = soup.find_all('a', href=re.compile(r'privacy|legal|terms|policy', re.I))
            if policy_links:
                privacy_signals["has_policy"] = True
                privacy_signals["score"] = 85
                policy_url = urljoin(url, policy_links[0]['href'])
                try:
                    p_res = requests.get(policy_url, timeout=2)
                    p_text = p_res.text.lower()
                    if 'gdpr' in p_text or 'ccpa' in p_text: privacy_signals["score"] += 10
                    if 'opt-out' in p_text or 'unsubscribe' in p_text: privacy_signals["score"] += 5
                except: pass
            
            return vulnerabilities, privacy_signals
        except:
            return vulnerabilities, privacy_signals

    def extract_url_features(self, url: str):
        parsed = urlparse(url)
        domain = parsed.netloc
        digits = sum(c.isdigit() for c in url)
        
        return {
            "length": len(url),
            "entropy": round(self.calculate_entropy(url), 2),
            "subdomain_count": domain.count('.'),
            "has_ip": 1 if bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)) else 0,
            "special_chars": len(re.findall(r'[@\-_\?&\.=]', url)),
            "digit_ratio": round(digits / len(url), 2) if len(url) > 0 else 0,
            "is_https": 1 if parsed.scheme == 'https' else 0,
            "suspicious_patterns": 1 if bool(re.search(r'(verify|account|secure|login|update|bank|paypal|signin)', url, re.I)) else 0
        }

analyzer = SecurityAnalyzer()

class ScanRequest(BaseModel):
    url: str
    scan_type: str = "full"

@app.post("/analyze")
async def analyze_url(request: ScanRequest):
    try:
        url = request.url
        is_full = request.scan_type == "full"
        
        # Multi-Vector Extraction
        url_f = analyzer.extract_url_features(url)
        vuln_f, privacy_f = await analyzer.fetch_and_analyze_content(url, full_audit=is_full)
        
        # Combine Features
        all_features = {**url_f, **vuln_f, "privacy_score": privacy_f["score"]}
        
        f_list = [all_features[k] for k in analyzer.feature_names]
        
        # ML Prediction
        prob = analyzer.model.predict_proba([f_list])[0][1]
        risk_score = int(prob * 100)
        
        # Heuristic Enhancements
        if not url_f["is_https"]: risk_score = max(risk_score, 65)
        if url_f["has_ip"]: risk_score = max(risk_score, 90)
        if vuln_f["missing_csp"]: risk_score = max(risk_score, 45)
        if vuln_f["missing_hsts"] and url_f["is_https"]: risk_score = max(risk_score, 50)
        
        if is_full:
            if vuln_f["hidden_iframes"] > 0: risk_score = max(risk_score, 75)
            if vuln_f["xss_patterns"] > 0: risk_score = max(risk_score, 85)
            if vuln_f["sqli_patterns"] > 0: risk_score = max(risk_score, 88)
            if vuln_f["redirect_loops"] > 0: risk_score = max(risk_score, 60)
            if privacy_f["score"] < 50: risk_score = max(risk_score, 40)

        # Status Logic
        if risk_score >= 80: status = "DANGEROUS"
        elif risk_score >= 55: status = "SUSPICIOUS"
        elif risk_score >= 35: status = "VULNERABLE" if not url_f["is_https"] else "MONITORED"
        else: status = "SECURE"

        # Generate AI Suggestions
        suggestions = []
        if vuln_f["missing_csp"]:
            suggestions.append({"issue": "Missing Content Security Policy", "fix": "No CSP found. Site is vulnerable to XSS and data injection.", "severity": "warning"})
        if vuln_f["missing_hsts"] and url_f["is_https"]:
            suggestions.append({"issue": "Missing HSTS Header", "fix": "Site is vulnerable to SSL Stripping attacks. Enable HTTP Strict Transport Security.", "severity": "warning"})
        if vuln_f["missing_xframe"]:
            suggestions.append({"issue": "Missing Clickjacking Protection", "fix": "X-Frame-Options not set. Attackers could overlay this site in an iframe.", "severity": "warning"})
            
        if is_full:
            if vuln_f["xss_patterns"] > 0:
                suggestions.append({"issue": "XSS Vulnerability Detector", "fix": "Suspicious Cross-Site Scripting patterns found. Protect session cookies.", "severity": "critical"})
            if vuln_f["sqli_patterns"] > 0:
                suggestions.append({"issue": "SQL Database Injection", "fix": "Potentially active injection vectors detected in URL/DOM.", "severity": "critical"})
            if vuln_f["redirect_loops"] > 0:
                suggestions.append({"issue": "Deceptive Redirect Loop", "fix": "Excessive or meta-refresh redirects detected. High phishing indicator.", "severity": "warning"})
            if vuln_f["hidden_iframes"] > 0:
                suggestions.append({"issue": "Hidden Malware Iframe", "fix": "Found hidden 0-pixel iframes. Standard malware tactic.", "severity": "critical"})
            if not privacy_f["has_policy"]:
                suggestions.append({"issue": "Missing Privacy Transparency", "fix": "No privacy policy found. Data privacy risk.", "severity": "warning"})

        if not url_f["is_https"]:
            suggestions.append({"issue": "Unencrypted Channel", "fix": "HTTP used. Data is visible to ISP and hackers.", "severity": "critical"})

        return {
            "risk_score": risk_score,
            "status_label": status,
            "is_suspicious": risk_score >= 50,
            "scan_type": request.scan_type,
            "features": all_features,
            "ai_suggestions": suggestions,
            "analysis_metadata": {
                "ai_engine": "Ensemble-MultiVector-v3.2",
                "vectors": ["Malware", "Phishing", "Privacy", "Headers", "XSS/SQLi"],
                "scan_mode": "Deep-Content" if is_full else "Fast-URL",
                "timestamp": time.time()
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
