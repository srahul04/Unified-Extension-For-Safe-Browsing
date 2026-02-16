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
            "hidden_iframes", "suspicious_scripts", "privacy_score"
        ]

    def _train_initial_model(self):
        # Synthetic data for Phishing, Malware, and Privacy signals
        # Features: [length, entropy, subdomains, has_ip, special, digit_ratio, https, patterns, iframes, scripts, privacy]
        data = [
            [20, 3.2, 1, 0, 2, 0.05, 1, 0, 0, 0, 90],  # Safe (Google)
            [80, 4.5, 4, 1, 10, 0.25, 0, 1, 2, 1, 10], # Dangerous Phish/Malware
            [15, 2.5, 1, 0, 1, 0.0, 1, 0, 0, 0, 85],   # Safe
            [120, 5.1, 5, 0, 15, 0.30, 0, 1, 1, 3, 5],  # Malware/Phish
            [45, 3.8, 2, 0, 5, 0.10, 1, 0, 0, 0, 70],   # Safe-ish
            [100, 4.8, 3, 1, 12, 0.20, 0, 1, 3, 2, 0],  # High Risk
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

    async def fetch_and_analyze_content(self, url: str):
        malware_signals = {"hidden_iframes": 0, "suspicious_scripts": 0}
        privacy_signals = {"has_policy": False, "score": 0}
        
        try:
            headers = {'User-Agent': 'WebGuard-Security-Audit/3.0'}
            response = requests.get(url, timeout=5, headers=headers)
            soup = BeautifulSoup(response.text, 'lxml')
            
            # 1. Malware Heuristics
            iframes = soup.find_all('iframe')
            for iframe in iframes:
                style = iframe.get('style', '').lower()
                if 'display:none' in style or 'visibility:hidden' in style or (iframe.get('width') == '0' or iframe.get('height') == '0'):
                    malware_signals["hidden_iframes"] += 1
            
            scripts = soup.find_all('script')
            suspicious_keywords = ['eval(', 'unescape(', 'document.write(unescape', 'base64']
            for script in scripts:
                content = script.string if script.string else ""
                if any(kw in content for kw in suspicious_keywords):
                    malware_signals["suspicious_scripts"] += 1
            
            # 2. Privacy Policy Auditor
            policy_links = soup.find_all('a', href=re.compile(r'privacy|legal|terms|policy', re.I))
            if policy_links:
                privacy_signals["has_policy"] = True
                privacy_signals["score"] = 85 # Base score for having one
                # Simple keyword check for data rights
                policy_url = urljoin(url, policy_links[0]['href'])
                try:
                    p_res = requests.get(policy_url, timeout=3)
                    p_text = p_res.text.lower()
                    if 'gdpr' in p_text or 'ccpa' in p_text: privacy_signals["score"] += 10
                    if 'opt-out' in p_text or 'unsubscribe' in p_text: privacy_signals["score"] += 5
                except: pass
            
            return malware_signals, privacy_signals
        except:
            return malware_signals, privacy_signals

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

@app.post("/analyze")
async def analyze_url(request: ScanRequest):
    try:
        url = request.url
        # Multi-Vector Extraction
        url_f = analyzer.extract_url_features(url)
        malware_f, privacy_f = await analyzer.fetch_and_analyze_content(url)
        
        # Combine Features
        all_features = {**url_f, **malware_f, "privacy_score": privacy_f["score"]}
        
        f_list = [all_features[k] for k in analyzer.feature_names]
        
        # ML Prediction
        prob = analyzer.model.predict_proba([f_list])[0][1]
        risk_score = int(prob * 100)
        
        # Heuristic Enhancements
        if not url_f["is_https"]: risk_score = max(risk_score, 65)
        if url_f["has_ip"]: risk_score = max(risk_score, 90)
        if malware_f["hidden_iframes"] > 0: risk_score = max(risk_score, 75)
        if privacy_f["score"] < 50: risk_score = max(risk_score, 40) # Lack of privacy is suspicious

        # Status Logic
        if risk_score >= 80: status = "DANGEROUS"
        elif risk_score >= 55: status = "SUSPICIOUS"
        elif risk_score >= 35: status = "VULNERABLE" if not url_f["is_https"] else "MONITORED"
        else: status = "SECURE"

        # Generate AI Suggestions based on vectors
        suggestions = []
        if malware_f["hidden_iframes"] > 0:
            suggestions.append({"issue": "Hidden Malware Iframe", "fix": "Found hidden 0-pixel iframes, often used for drive-by-downloads. Avoid this site.", "severity": "critical"})
        if malware_f["suspicious_scripts"] > 0:
            suggestions.append({"issue": "Obfuscated Scripts", "fix": "Script execution contains eval/base64 patterns typical of crypto-jackers or malware.", "severity": "critical"})
        if not privacy_f["has_policy"]:
            suggestions.append({"issue": "Missing Privacy Transparency", "fix": "No privacy policy detected. Your data may be collected without consent.", "severity": "warning"})
        if not url_f["is_https"]:
            suggestions.append({"issue": "Unencrypted Channel", "fix": "HTTP used. Data is visible to ISP and hackers.", "severity": "critical"})

        return {
            "risk_score": risk_score,
            "status_label": status,
            "is_suspicious": risk_score >= 50,
            "features": all_features,
            "ai_suggestions": suggestions,
            "analysis_metadata": {
                "ai_engine": "Ensemble-MultiVector-v3.0",
                "vectors": ["Malware", "Phishing", "Privacy"],
                "timestamp": time.time()
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
