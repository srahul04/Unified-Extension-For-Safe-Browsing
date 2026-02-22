from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import re
from urllib.parse import urlparse, urljoin
import math
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
import pandas as pd
import uvicorn
import httpx
import asyncio
import time
from bs4 import BeautifulSoup
from functools import lru_cache

app = FastAPI(title="WebGuard AI-ML Analysis Service v3.5")

# Advanced ML Model with URL Semantic Analysis
class SecurityAnalyzer:
    def __init__(self):
        # Numerical/Structural features
        self.feature_names = [
            "length", "entropy", "subdomain_count", "has_ip", 
            "special_chars", "digit_ratio", "is_https", "suspicious_patterns",
            "hidden_iframes", "suspicious_scripts", "privacy_score",
            "xss_patterns", "sqli_patterns", "redirect_loops",
            "missing_csp", "missing_hsts", "missing_xframe",
            "domain_depth", "has_favicon", "is_punycode", "is_ecc", "is_high_risk_geo",
            "sri_score", "csp_strength_score"
        ]
        
        # TF-IDF Vectorizer for URL semantic analysis
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=100)
        
        self.model = self._train_advanced_model()
        self.client = httpx.AsyncClient(timeout=5.0, follow_redirects=True, headers={'User-Agent': 'WebGuard-AI-Core/3.5'})

    def _train_advanced_model(self):
        # Richer training set covering semantic URL patterns
        # [length, entropy, subdomains, has_ip, special, digit_ratio, https, patterns, iframes, scripts, privacy, xss, sqli, redirects, csp, hsts, xframe, depth, favicon, punycode, ecc, geo]
        training_urls = [
            "https://google.com/", "https://github.com/login", "https://amazon.com/orders",
            "http://192.168.1.1/login", "http://verify-paypal-account-support.com/update",
            "https://secure-bank-login.k-net.site/login.php", "http://login.microsoftonline.com.re-auth.net/",
            "https://appleid.apple.com/", "http://xn--80ak6aa92e.com/", # punycode example
            "https://facebook.com/messages", "http://update-your-account-now.info/",
            "https://wellsfargo.com/", "http://net-banking-secure.cc/portal"
        ]
        
        # Labels: 0 for safe, 1 for malicious/suspicious
        labels = [0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1]
        
        # Extract numerical features for training
        num_features = []
        for url in training_urls:
            f = self.extract_url_features(url)
            # Mocking some browser/header/crypto/geo features for training data stability
            mock_vuln = {"hidden_iframes": 0, "suspicious_scripts": 0, "xss_patterns": 0, "sqli_patterns": 0, "redirect_loops": 0, "missing_csp": 0, "missing_hsts": 0, "missing_xframe": 0, "has_favicon": 1, "is_ecc": 1, "is_high_risk_geo": 0}
            if labels[training_urls.index(url)] == 1:
                mock_vuln = {"hidden_iframes": 2, "suspicious_scripts": 1, "xss_patterns": 0, "sqli_patterns": 1, "redirect_loops": 1, "missing_csp": 1, "missing_hsts": 1, "missing_xframe": 1, "has_favicon": 0, "is_ecc": 0, "is_high_risk_geo": 1}
            
            combined = {**f, **mock_vuln, "privacy_score": 90 if labels[training_urls.index(url)] == 0 else 10}
            num_features.append([combined[k] for k in self.feature_names])
            
        # Fit URL vectorizer
        self.vectorizer.fit(training_urls)
        url_vecs = self.vectorizer.transform(training_urls).toarray()
        
        # Combine numerical and semantic features
        X = np.hstack([np.array(num_features), url_vecs])
        
        clf = GradientBoostingClassifier(n_estimators=200, learning_rate=0.1, max_depth=5, random_state=42)
        clf.fit(X, np.array(labels))
        return clf

    @lru_cache(maxsize=128)
    def calculate_entropy(self, text: str) -> float:
        if not text: return 0
        arr = np.array(list(text))
        _, counts = np.unique(arr, return_counts=True)
        probs = counts / len(text)
        return -np.sum(probs * np.log2(probs))

    async def fetch_and_analyze_content(self, url: str, full_audit: bool = True):
        vulnerabilities = {
            "hidden_iframes": 0, "suspicious_scripts": 0, "xss_patterns": 0,
            "sqli_patterns": 0, "redirect_loops": 0,
            "missing_csp": 0, "missing_hsts": 0, "missing_xframe": 0,
            "has_favicon": 0, "is_ecc": 0, "is_high_risk_geo": 0,
            "sri_score": 0, "csp_strength_score": 0
        }
        privacy_signals = {"has_policy": False, "score": 0}
        ssl_info = {"algorithm": "Unknown", "curve": "N/A", "strength": "Low"}
        infra_info = {"ip": "Unknown", "country": "Unknown", "city": "Unknown", "isp": "Unknown", "flag": "🏳️"}
        extra_security = {"sri_percentage": 0, "csp_grade": "None", "headers": []}
        
        try:
            # Infrastructure & Geolocation Analysis
            parsed = urlparse(url)
            hostname = parsed.hostname
            if hostname:
                try:
                    import socket
                    ip_addr = socket.gethostbyname(hostname)
                    infra_info["ip"] = ip_addr
                    
                    # Async GEO Lookup (ip-api.com is free for non-commercial/low rate)
                    async with httpx.AsyncClient(timeout=3.0) as client:
                        geo_res = await client.get(f"http://ip-api.com/json/{ip_addr}")
                        if geo_res.status_code == 200:
                            g = geo_res.json()
                            if g.get("status") == "success":
                                infra_info.update({
                                    "country": g.get("country", "Unknown"),
                                    "city": g.get("city", "Unknown"),
                                    "isp": g.get("isp", "Unknown"),
                                    "flag": f"https://flagcdn.com/24x18/{g.get('countryCode', 'us').lower()}.png"
                                })
                                # Heuristic: Detect high-risk regions for phishing clusters
                                if g.get("countryCode") in ["RU", "CN", "NG", "VN"]:
                                    vulnerabilities["is_high_risk_geo"] = 1
                except Exception as e:
                    print(f"Geo Lookup Error: {e}")

            # SSL / ECC Certificate Analysis
            if parsed.scheme == 'https':
                try:
                    import ssl
                    import socket
                    hostname = parsed.hostname
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, 443), timeout=2) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cipher = ssock.cipher()
                            ssl_info["algorithm"] = cipher[0]
                            # Simple ECC detection via cipher name
                            if any(x in cipher[0] for x in ['ECDHE', 'ECDSA', 'ECC']):
                                vulnerabilities["is_ecc"] = 1
                                ssl_info["strength"] = "High (ECC)"
                            else:
                                ssl_info["strength"] = "Medium (RSA/Standard)"
                except Exception as e:
                    print(f"SSL Check Error: {e}")

            # Pattern checking
            if re.search(r'(<script|alert\(|onerror=|<img|javascript:)', url, re.I):
                vulnerabilities["xss_patterns"] += 1

            if not full_audit:
                response = await self.client.head(url)
                vulnerabilities.update({
                    "missing_csp": 1 if 'Content-Security-Policy' not in response.headers else 0,
                    "missing_hsts": 1 if 'Strict-Transport-Security' not in response.headers else 0,
                    "missing_xframe": 1 if 'X-Frame-Options' not in response.headers else 0
                })
                return vulnerabilities, privacy_signals, ssl_info, infra_info

            response = await self.client.get(url)
            vulnerabilities.update({
                "missing_csp": 1 if 'Content-Security-Policy' not in response.headers else 0,
                "missing_hsts": 1 if 'Strict-Transport-Security' not in response.headers else 0,
                "missing_xframe": 1 if 'X-Frame-Options' not in response.headers else 0
            })
            
            soup = BeautifulSoup(response.text, 'lxml')
            vulnerabilities["has_favicon"] = 1 if soup.find('link', rel=re.compile(r'icon', re.I)) else 0
            
            if len(response.history) > 2: vulnerabilities["redirect_loops"] += 1
            if soup.find('meta', attrs={'http-equiv': 'refresh'}): vulnerabilities["redirect_loops"] += 1

            iframes = soup.find_all('iframe')
            for iframe in iframes:
                style = iframe.get('style', '').lower()
                if any(x in style for x in ['display:none', 'visibility:hidden']) or (iframe.get('width') == '0' or iframe.get('height') == '0'):
                    vulnerabilities["hidden_iframes"] += 1
            
            scripts = soup.find_all('script')
            suspicious_keywords = ['eval(', 'unescape(', 'document.write(', 'base64', 'String.fromCharCode']
            for script in scripts:
                content = script.string if script.string else ""
                if any(kw in content for kw in suspicious_keywords):
                    vulnerabilities["suspicious_scripts"] += 1
            
            if soup.find('a', href=re.compile(r'privacy|legal|terms|policy', re.I)):
                privacy_signals["has_policy"] = True
                privacy_signals["score"] = 85
            
            # --- Extra Security Features ---
            
            # 1. SRI (Subresource Integrity) Check
            scripts_with_src = soup.find_all('script', src=True)
            links_with_href = soup.find_all('link', rel='stylesheet', href=True)
            total_subresources = len(scripts_with_src) + len(links_with_href)
            if total_subresources > 0:
                sri_count = sum(1 for el in scripts_with_src + links_with_href if el.get('integrity'))
                sri_percent = (sri_count / total_subresources) * 100
                vulnerabilities["sri_score"] = int(sri_percent)
                extra_security["sri_percentage"] = int(sri_percent)

            # 2. CSP Strength Analysis
            csp_header = response.headers.get('Content-Security-Policy', '')
            if csp_header:
                csp_score = 100
                risky_directives = ["'unsafe-inline'", "'unsafe-eval'", "data:", "http:"]
                for risky in risky_directives:
                    if risky in csp_header:
                        csp_score -= 20
                
                # Check for overly permissive wildcards
                if "* " in csp_header or " *" in csp_header:
                    csp_score -= 15
                
                vulnerabilities["csp_strength_score"] = max(0, csp_score)
                extra_security["csp_grade"] = "Strong" if csp_score >= 90 else "Moderate" if csp_score >= 70 else "Weak"
            else:
                vulnerabilities["csp_strength_score"] = 0
                extra_security["csp_grade"] = "Missing"

            # 3. Additional Headers
            extra_security["headers"] = {
                "Permissions-Policy": "present" if 'Permissions-Policy' in response.headers else "missing",
                "Referrer-Policy": response.headers.get('Referrer-Policy', 'missing')
            }

            return vulnerabilities, privacy_signals, ssl_info, infra_info, extra_security
        except Exception:
            return vulnerabilities, privacy_signals, ssl_info, infra_info, extra_security

    def extract_url_features(self, url: str):
        parsed = urlparse(url)
        domain = parsed.netloc
        
        return {
            "length": len(url),
            "entropy": round(self.calculate_entropy(url), 2),
            "subdomain_count": domain.count('.'),
            "has_ip": 1 if bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)) else 0,
            "special_chars": len(re.findall(r'[@\-_\?&\.=]', url)),
            "digit_ratio": round(sum(c.isdigit() for c in url) / len(url), 2) if len(url) > 0 else 0,
            "is_https": 1 if parsed.scheme == 'https' else 0,
            "suspicious_patterns": 1 if bool(re.search(r'(verify|account|secure|login|update|bank|paypal|signin|confirm)', url, re.I)) else 0,
            "domain_depth": len([x for x in parsed.path.split('/') if x]),
            "is_punycode": 1 if domain.startswith('xn--') else 0
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
        
        # 1. Structural/Behavioral Features
        url_f = analyzer.extract_url_features(url)
        vuln_f, privacy_f, ssl_f, infra_f, extra_f = await analyzer.fetch_and_analyze_content(url, full_audit=is_full)
        
        combined_num = {**url_f, **vuln_f, "privacy_score": privacy_f["score"]}
        num_vec = [combined_num[k] for k in analyzer.feature_names]
        
        # 2. Semantic URL Analysis (TF-IDF)
        semantic_vec = analyzer.vectorizer.transform([url]).toarray()[0]
        
        # 3. Hybrid ML Inference
        X_final = np.hstack([np.array(num_vec), semantic_vec])
        prob = analyzer.model.predict_proba([X_final])[0][1]
        
        # Boost risk if semantic vibe is strong or specific patterns exist
        risk_score = int(prob * 100)
        
        # 4. Critical Heuristic Overrides (Safety Rails)
        if not url_f["is_https"]: risk_score = max(risk_score, 65)
        if url_f["has_ip"]: risk_score = max(risk_score, 95)
        if url_f["is_punycode"]: risk_score = max(risk_score, 85)
        
        if is_full:
            if vuln_f["hidden_iframes"] > 2: risk_score = max(risk_score, 80)
            if vuln_f["suspicious_scripts"] > 1: risk_score = max(risk_score, 75)

        # 5. Cryptographic Analysis (ECC)
        if url_f["is_https"] and not vuln_f["is_ecc"]:
            if url_f["suspicious_patterns"]:
                risk_score = min(risk_score + 10, 100)

        # 6. Infrastructure & GEO Heuristics
        if vuln_f["is_high_risk_geo"]:
            if url_f["suspicious_patterns"]:
                risk_score = min(risk_score + 15, 100)

        status = "SECURE"
        if risk_score >= 80: status = "DANGEROUS"
        elif risk_score >= 50: status = "SUSPICIOUS"
        elif risk_score >= 30: status = "VULNERABLE"
        
        return {
            "risk_score": risk_score,
            "status_label": status,
            "is_suspicious": risk_score >= 50,
            "scan_type": request.scan_type,
            "features": combined_num,
            "cryptography": ssl_f,
            "infrastructure": infra_f,
            "extra_security": extra_f,
            "ai_suggestions": [
                {"issue": "Advanced Phishing Pattern", "fix": "Highly suspicious URL structure detected by Gradient Boosting engine.", "severity": "critical"}
            ] if risk_score > 70 else [],
            "analysis_metadata": {
                "ai_engine": "Ensemble-GBC-TFIDF-v3.5 + ECC-Inspector + Geo-Sentinel + Extra-Audit-v1",
                "timestamp": time.time(),
                "performance": "char-ngram-vectorization"
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
