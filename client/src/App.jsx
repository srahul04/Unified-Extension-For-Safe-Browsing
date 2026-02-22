import { useState, useEffect } from 'react';
import { Shield, Zap, Activity, Download, Settings, ChevronRight, AlertTriangle, CheckCircle, FileText, Lock, Globe } from 'lucide-react';
import axios from 'axios';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { motion, AnimatePresence } from 'framer-motion';
import './App.css';

const API_BASE = 'http://localhost:5000/api';

function App() {
    const [view, setView] = useState('dashboard');
    const [subView, setSubView] = useState('audit'); // 'audit', 'privacy', 'history'
    const [scanResults, setScanResults] = useState(null);
    const [isScanning, setIsScanning] = useState(false);
    const [progress, setProgress] = useState(0);
    const [gaugeKey, setGaugeKey] = useState(0);
    const [history, setHistory] = useState([]);
    const [whitelist, setWhitelist] = useState([]);
    const [newWhitelistDomain, setNewWhitelistDomain] = useState('');
    const [settings, setSettings] = useState({
        defaultScanType: 'full',
        autoScan: true,
        notifications: true,
        theme: 'dark'
    });

    // Listen for async VirusTotal updates
    useEffect(() => {
        const handleMessage = (message) => {
            if (message.action === 'updateVTResults' && scanResults && message.url === scanResults.url) {
                setScanResults(prev => ({
                    ...prev,
                    vt_results: message.vtResult
                }));
            }
        };
        chrome.runtime.onMessage.addListener(handleMessage);
        return () => chrome.runtime.onMessage.removeListener(handleMessage);
    }, [scanResults]);

    // Load initialization data
    useEffect(() => {
        const loadInitData = async () => {
            if (typeof chrome !== 'undefined' && chrome.storage) {
                chrome.storage.local.get(['webguard_settings', 'scanHistory', 'webguard_whitelist'], (result) => {
                    if (result.webguard_settings) setSettings(result.webguard_settings);
                    if (result.scanHistory) setHistory(result.scanHistory);
                    if (result.webguard_whitelist) setWhitelist(result.webguard_whitelist);
                });
            } else {
                const saved = localStorage.getItem('webguard_settings');
                if (saved) setSettings(JSON.parse(saved));
                const savedHistory = localStorage.getItem('scanHistory');
                if (savedHistory) setHistory(JSON.parse(savedHistory));
                const savedWhitelist = localStorage.getItem('webguard_whitelist');
                if (savedWhitelist) setWhitelist(JSON.parse(savedWhitelist));
            }
        };
        loadInitData();
    }, []);

    const updateSetting = (key, value) => {
        const newSettings = { ...settings, [key]: value };
        setSettings(newSettings);
        if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.set({ webguard_settings: newSettings });
        } else {
            localStorage.setItem('webguard_settings', JSON.stringify(newSettings));
        }
    };

    const restartGaugeAnimation = () => setGaugeKey(prev => prev + 1);

    const startScan = async (type = 'full') => {
        setIsScanning(true);
        setProgress(10);

        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

            // Collect resources for tracker detection
            const resources = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: () => performance.getEntriesByType('resource').map(r => r.name)
            });

            // Send scan request to background
            chrome.runtime.sendMessage({
                action: 'performComprehensiveAudit',
                url: tab.url,
                scan_type: type,
                resources: resources[0].result
            }, (response) => {
                if (response && response.success) {
                    if (response.whitelisted) {
                        alert('This site is in your whitelist and will not be scanned.');
                        setIsScanning(false);
                        return;
                    }

                    setProgress(100);
                    // Mocking backend response format for ML as it was previously using axios.post
                    // Note: The original App.jsx used axios.post(`${API_BASE}/scan`, ...) 
                    // which means it was hit the external API.
                    // But we also have background.js logic. Let's unify it.

                    const scanData = {
                        url: tab.url,
                        ml_results: {
                            risk_score: response.phishing.riskScore,
                            status_label: response.phishing.severity.toUpperCase(),
                            ai_suggestions: response.phishing.indicators.map(ind => ({
                                issue: ind,
                                fix: "Follow security best practices",
                                severity: response.phishing.severity
                            })),
                            features: {
                                ssl: response.headers.present.some(h => h.name.includes('HTTPS')) ? 1 : 0,
                                trackers: response.trackers.totalTrackers,
                                cookies: response.cookies.total
                            },
                            scan_type: type,
                            trackers: response.trackers
                        },
                        timestamp: new Date().toISOString()
                    };

                    setScanResults(scanData);
                    saveToHistory(scanData);

                    setTimeout(() => {
                        setIsScanning(false);
                        setSubView('audit');
                    }, 500);
                } else {
                    throw new Error(response?.error || 'Scan failed');
                }
            });

        } catch (error) {
            console.error('Scan failed:', error);
            setIsScanning(false);
            alert('Scan failed: ' + error.message);
        }
    };

    const saveToHistory = (scanData) => {
        const newHistory = [scanData, ...history.slice(0, 49)];
        setHistory(newHistory);
        if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.set({ scanHistory: newHistory });
        } else {
            localStorage.setItem('scanHistory', JSON.stringify(newHistory));
        }
    };

    const addToWhitelist = () => {
        if (!newWhitelistDomain) return;
        const newWhitelist = [...whitelist, newWhitelistDomain];
        setWhitelist(newWhitelist);
        setNewWhitelistDomain('');
        if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.set({ webguard_whitelist: newWhitelist });
        } else {
            localStorage.setItem('webguard_whitelist', JSON.stringify(newWhitelist));
        }
    };

    const removeFromWhitelist = (domain) => {
        const newWhitelist = whitelist.filter(d => d !== domain);
        setWhitelist(newWhitelist);
        if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.set({ webguard_whitelist: newWhitelist });
        } else {
            localStorage.setItem('webguard_whitelist', JSON.stringify(newWhitelist));
        }
    };

    const generateReport = () => {
        if (!scanResults) {
            alert('No scan results available. Please run a scan first.');
            return;
        }

        try {
            const doc = new jsPDF();
            const timestamp = new Date().toLocaleString();
            const ml = scanResults.ml_results || {};
            const status = ml.status_label || 'SCANNING';

            // Define colors based on status
            const statusColor = status === 'SECURE' ? [34, 197, 94] : // Green
                status === 'VULNERABLE' ? [239, 68, 68] : // Red
                    status === 'SUSPICIOUS' ? [249, 115, 22] : // Orange
                        [239, 68, 68]; // Red for Dangerous

            // Header Banner
            doc.setFillColor(statusColor[0], statusColor[1], statusColor[2]);
            doc.rect(0, 0, 210, 40, 'F');
            doc.setTextColor(255, 255, 255);
            doc.setFontSize(22);
            doc.text('WebGuard v2.2 Security Audit', 15, 25);
            doc.setFontSize(10);
            doc.text(`Generated: ${timestamp}`, 150, 25);

            // Scan Summary
            doc.setTextColor(0, 0, 0);
            doc.setFontSize(16);
            doc.text('1. Scan Summary', 15, 55);

            doc.setFontSize(11);
            doc.text(`Target URL:`, 15, 65);
            doc.setFont(undefined, 'bold');
            doc.text(`${scanResults.url || 'Unknown'}`, 45, 65);
            doc.setFont(undefined, 'normal');

            doc.text(`Risk Score:`, 15, 75);
            doc.text(`${ml.risk_score || 0}/100`, 45, 75);

            doc.text(`Scan Mode:`, 15, 85);
            doc.text(`${(scanResults.ml_results?.scan_type || 'full').toUpperCase()}`, 45, 85);

            doc.text(`Safety Status:`, 15, 95);
            doc.setTextColor(statusColor[0], statusColor[1], statusColor[2]);
            doc.setFont(undefined, 'bold');
            doc.text(`${status}`, 45, 95);
            doc.setTextColor(0, 0, 0);
            doc.setFont(undefined, 'normal');

            // AI Fix Suggestions
            doc.setFontSize(16);
            doc.text('2. AI-Driven Fix Suggestions', 15, 105);

            const suggestionData = (ml.ai_suggestions || []).map(s => [
                s.issue || 'Unknown Issue',
                s.fix || 'N/A',
                (s.severity || 'UNKNOWN').toUpperCase()
            ]);

            autoTable(doc, {
                startY: 110,
                head: [['Security Issue', 'Recommended Fix', 'Severity']],
                body: suggestionData.length > 0 ? suggestionData : [['N/A', 'Your website follows encryption best practices. No critical loopholes identified.', 'SAFE']],
                theme: 'grid',
                headStyles: { fillStyle: statusColor },
                styles: { fontSize: 10 }
            });

            // Technical Features
            const endY = doc.lastAutoTable.finalY + 15;
            doc.setFontSize(16);
            doc.text('3. Technical Signal Analysis', 15, endY);

            const featureData = Object.entries(ml.features || {}).map(([key, val]) => [
                key.replace(/_/g, ' ').toUpperCase(),
                String(val)
            ]);

            autoTable(doc, {
                startY: endY + 5,
                head: [['ML Feature Signal', 'Extracted Value']],
                body: featureData,
                theme: 'striped',
                headStyles: { fillStyle: [100, 116, 139] },
                styles: { fontSize: 9 }
            });

            // Metadata
            const finalY = doc.lastAutoTable.finalY + 15;
            doc.setFontSize(10);
            doc.setTextColor(100, 116, 139);
            const aiEngine = ml.analysis_metadata?.ai_engine || 'Standard Heuristic';
            doc.text(`Analysis Engine: Random Forest v2.0 | Status: ${aiEngine}`, 15, finalY);

            doc.save(`WebGuard_Audit_Report_${Date.now()}.pdf`);
        } catch (err) {
            console.error('PDF Generation Error:', err);
            alert(`Failed to generate report: ${err.message}`);
        }
    };

    return (
        <div className="app-container">
            <AnimatePresence>
                {view === 'dashboard' && (
                    <motion.div
                        className="dashboard"
                        initial={{ opacity: 0, scale: 0.95, y: 10 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        transition={{ duration: 0.4, ease: "easeOut" }}
                    >
                        <header className="header">
                            <motion.div
                                className="brand"
                                initial={{ x: -20, opacity: 0 }}
                                animate={{ x: 0, opacity: 1 }}
                                transition={{ delay: 0.2 }}
                            >
                                <Shield className="brand-icon" size={24} />
                                <span>WebGuard v2.2</span>
                            </motion.div>
                            <motion.div
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                transition={{ delay: 0.3 }}
                                onClick={() => setView('settings')}
                                style={{ cursor: 'pointer' }}
                            >
                                <Settings className="settings-icon" size={20} />
                            </motion.div>
                        </header>

                        <div className="nav-tabs">
                            <div className={`nav-tab ${subView === 'audit' ? 'active' : ''}`} onClick={() => setSubView('audit')}>Security</div>
                            <div className={`nav-tab ${subView === 'privacy' ? 'active' : ''}`} onClick={() => setSubView('privacy')}>Privacy</div>
                            <div className={`nav-tab ${subView === 'history' ? 'active' : ''}`} onClick={() => setSubView('history')}>History</div>
                        </div>

                        {subView === 'audit' && (
                            <>
                                <section className="score-section">
                                    <div className="gauge-outer" onMouseEnter={restartGaugeAnimation}>
                                        <svg className="gauge-svg" viewBox="0 0 140 140">
                                            <circle className="gauge-bg" cx="70" cy="70" r="60" strokeWidth="8" />
                                            <motion.circle
                                                key={gaugeKey}
                                                className="gauge-progress"
                                                cx="70" cy="70" r="60"
                                                strokeWidth="8"
                                                initial={{ strokeDashoffset: 377 }}
                                                animate={{
                                                    strokeDashoffset: 377 - (377 * (scanResults?.ml_results?.risk_score || 0) / 100)
                                                }}
                                                transition={{ duration: 1.5, ease: "circOut" }}
                                                style={{
                                                    stroke: scanResults ? (
                                                        scanResults.ml_results.status_label === 'SECURE' ? '#22c55e' :
                                                            scanResults.ml_results.status_label === 'VULNERABLE' ? '#ef4444' :
                                                                scanResults.ml_results.status_label === 'SUSPICIOUS' ? '#f97316' :
                                                                    '#ef4444'
                                                    ) : '#e2e8f0'
                                                }}
                                            />
                                        </svg>
                                        <motion.div
                                            className={`score-value ${scanResults?.ml_results?.status_label?.toLowerCase()}`}
                                            key={`score-${gaugeKey}`}
                                            initial={{ scale: 0.5, opacity: 0, x: "-50%", y: "-50%" }}
                                            animate={{ scale: 1, opacity: 1, x: "-50%", y: "-50%" }}
                                            transition={{ delay: 0.2, type: "spring", stiffness: 200 }}
                                            style={{
                                                position: 'absolute',
                                                top: '50%',
                                                left: '50%'
                                            }}
                                        >
                                            {scanResults?.ml_results?.risk_score ?? 0}
                                        </motion.div>
                                    </div>
                                    <h2 className={`status-title ${scanResults?.ml_results?.status_label?.toLowerCase()}`}>
                                        {scanResults ? (
                                            scanResults.ml_results.status_label === 'SECURE' ? 'Site is Secure' :
                                                scanResults.ml_results.status_label === 'SUSPICIOUS' ? 'Suspicious Activity' :
                                                    scanResults.ml_results.status_label === 'VULNERABLE' ? 'Insecure Loophole' :
                                                        'Dangerous Site'
                                        ) : 'System Ready'}
                                    </h2>
                                    {scanResults && (
                                        <motion.div
                                            className="target-url-badge truncate"
                                            initial={{ opacity: 0, y: 5 }}
                                            animate={{ opacity: 1, y: 0 }}
                                            transition={{ delay: 0.3 }}
                                        >
                                            <span>Scanning:</span> {scanResults.url}
                                        </motion.div>
                                    )}
                                    <p className="status-subtitle">Advanced ML Loophole Analysis</p>
                                </section>

                                <motion.section
                                    className="monitoring-card"
                                    initial={{ opacity: 0, y: 20 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: 0.4 }}
                                >
                                    <div className="card-top">
                                        <div className="mon-info">
                                            <h3>Real-time Monitoring</h3>
                                            <div className="mon-status">
                                                <CheckCircle size={14} className="success-icon" />
                                                <span>Active protection enabled</span>
                                            </div>
                                        </div>
                                        <div
                                            className={`toggle ${settings.autoScan ? 'active' : ''}`}
                                            onClick={() => updateSetting('autoScan', !settings.autoScan)}
                                        >
                                            <div className="toggle-thumb" />
                                        </div>
                                    </div>
                                </motion.section>

                                <section className="results-section">
                                    {scanResults?.vt_results && (
                                        <motion.div
                                            className="threat-intel-card"
                                            initial={{ opacity: 0, scale: 0.95 }}
                                            animate={{ opacity: 1, scale: 1 }}
                                        >
                                            <div className="intel-header">
                                                <Activity size={16} />
                                                <span>Threat Intelligence (VirusTotal)</span>
                                            </div>
                                            <div className="intel-stats">
                                                <div className="intel-stat malicious">
                                                    <span className="count">{scanResults.vt_results.malicious}</span>
                                                    <span className="label">Malicious</span>
                                                </div>
                                                <div className="intel-stat suspicious">
                                                    <span className="count">{scanResults.vt_results.suspicious}</span>
                                                    <span className="label">Suspicious</span>
                                                </div>
                                                <div className="intel-stat harmless">
                                                    <span className="count">{scanResults.vt_results.harmless}</span>
                                                    <span className="label">Clean</span>
                                                </div>
                                            </div>
                                            {scanResults.vt_results.not_found && (
                                                <div className="intel-footer">No prior analysis found; site is relatively new or unindexed.</div>
                                            )}
                                        </motion.div>
                                    )}
                                    {scanResults?.infrastructure && (
                                        <motion.div
                                            className="tech-intel-card infra-card"
                                            initial={{ opacity: 0, x: 20 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            transition={{ delay: 0.1 }}
                                        >
                                            <div className="intel-header">
                                                <Globe size={14} />
                                                <span>Server Insights</span>
                                                <img src={scanResults.infrastructure.flag} alt="flag" className="country-flag" onError={(e) => e.target.style.display = 'none'} />
                                            </div>
                                            <div className="tech-row">
                                                <span className="tech-label">Location:</span>
                                                <span className="tech-value">{scanResults.infrastructure.city}, {scanResults.infrastructure.country}</span>
                                            </div>
                                            <div className="tech-row">
                                                <span className="tech-label">Provider:</span>
                                                <span className="tech-value truncate-tech" title={scanResults.infrastructure.isp}>
                                                    {scanResults.infrastructure.isp}
                                                </span>
                                            </div>
                                        </motion.div>
                                    )}

                                    {scanResults?.cryptography && (
                                        <motion.div
                                            className="tech-intel-card crypto-card"
                                            initial={{ opacity: 0, x: 20 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            transition={{ delay: 0.2 }}
                                        >
                                            <div className="intel-header">
                                                <Lock size={14} />
                                                <span>Encryption Details</span>
                                            </div>
                                            <div className="tech-row">
                                                <span className="tech-label">Algorithm:</span>
                                                <span className="tech-value">{scanResults.cryptography.algorithm}</span>
                                            </div>
                                            <div className="tech-row">
                                                <span className="tech-label">Strength:</span>
                                                <span className={`tech-value ${scanResults.cryptography.is_ecc ? 'ecc-high' : ''}`}>
                                                    {scanResults.cryptography.strength}
                                                </span>
                                            </div>
                                        </motion.div>
                                    )}

                                    {scanResults?.integrity && (
                                        <motion.div
                                            className="tech-intel-card integrity-card"
                                            initial={{ opacity: 0, x: -20 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            transition={{ delay: 0.3 }}
                                        >
                                            <div className="intel-header">
                                                <CheckCircle size={14} color="#22c55e" />
                                                <span>Audit Integrity</span>
                                            </div>
                                            <div className="sig-box">
                                                <span className="sig-label">Digital Signature:</span>
                                                <code className="sig-value">{scanResults.integrity.signature.substring(0, 24)}...</code>
                                            </div>
                                            <div className="sig-algo">Signed with Ed25519 (ECC)</div>
                                        </motion.div>
                                    )}

                                    <h3 className="section-title">AI Loophole Analysis</h3>
                                    <div className="audit-list">
                                        {scanResults ? (
                                            <>
                                                {scanResults.ml_results?.ai_suggestions?.map((s, i) => (
                                                    <motion.div
                                                        key={i}
                                                        className={`audit-item suggestion-card ${s.severity}`}
                                                        initial={{ opacity: 0, x: -20 }}
                                                        animate={{ opacity: 1, x: 0 }}
                                                        transition={{ delay: 0.5 + (i * 0.1) }}
                                                        whileHover={{ x: 5, backgroundColor: "rgba(255,255,255,0.8)" }}
                                                    >
                                                        <div className="audit-icon">
                                                            {s.severity === 'critical' ? <AlertTriangle size={20} /> : <FileText size={20} />}
                                                        </div>
                                                        <div className="audit-info">
                                                            <div className="audit-name">{s.issue}</div>
                                                            <div className="audit-status truncate">{s.fix}</div>
                                                        </div>
                                                    </motion.div>
                                                ))}
                                                {(!scanResults.ml_results?.ai_suggestions || scanResults.ml_results.ai_suggestions.length === 0) && (
                                                    <motion.div
                                                        className="audit-item"
                                                        initial={{ opacity: 0 }}
                                                        animate={{ opacity: 1 }}
                                                        transition={{ delay: 0.5 }}
                                                    >
                                                        <div className="audit-icon icon-emerald"><Shield size={20} /></div>
                                                        <div className="audit-info">
                                                            <div className="audit-name">Security Profile: Strong</div>
                                                            <div className="audit-status">No immediate loopholes found.</div>
                                                        </div>
                                                    </motion.div>
                                                )}
                                            </>
                                        ) : (
                                            <motion.div
                                                className="empty-state"
                                                initial={{ opacity: 0 }}
                                                animate={{ opacity: 1 }}
                                            >
                                                Scan a website to identify loopholes.
                                            </motion.div>
                                        )}
                                    </div>
                                </section>

                                <motion.section
                                    className="actions"
                                    initial={{ opacity: 0, y: 20 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: 0.6 }}
                                >
                                    <button className="btn btn-primary" onClick={() => startScan('quick')}>
                                        <Zap size={18} /> Quick Scan
                                    </button>
                                    <button className="btn btn-secondary" onClick={() => startScan('full')}>
                                        Full Security Audit
                                    </button>
                                    {scanResults && (
                                        <motion.button
                                            className="btn btn-report"
                                            onClick={generateReport}
                                            initial={{ scale: 0.9, opacity: 0 }}
                                            animate={{ scale: 1, opacity: 1 }}
                                            whileHover={{ scale: 1.02, y: -2 }}
                                            whileTap={{ scale: 0.98 }}
                                        >
                                            <Download size={18} /> Generate Detailed Report
                                        </motion.button>
                                    )}
                                </motion.section>
                            </>
                        )}

                        {subView === 'privacy' && (
                            <div className="scroll-view">
                                <section className="results-section">
                                    <h3 className="section-title">Privacy Insights</h3>
                                    {!scanResults?.ml_results?.trackers ? (
                                        <div className="empty-state">Scan a site to see privacy insights.</div>
                                    ) : (
                                        <div className="audit-list">
                                            <div className="monitoring-card" style={{ margin: '0 0 16px 0' }}>
                                                <div className="stats-grid">
                                                    <div className="stat-box">
                                                        <span className="label">Privacy Score</span>
                                                        <span className="value" style={{ color: scanResults.ml_results.trackers.privacyScore > 70 ? '#22c55e' : '#f97316' }}>
                                                            {scanResults.ml_results.trackers.privacyScore}
                                                        </span>
                                                    </div>
                                                    <div className="stat-box">
                                                        <span className="label">Trackers</span>
                                                        <span className="value">{scanResults.ml_results.trackers.totalTrackers}</span>
                                                    </div>
                                                </div>
                                            </div>
                                            {scanResults.ml_results.trackers.trackers.map((t, i) => (
                                                <div key={i} className="tracker-item">
                                                    <div className="tracker-icon"><Activity size={16} /></div>
                                                    <div className="tracker-info">
                                                        <div className="tracker-domain">{t.domain}</div>
                                                        <div className="tracker-type">{t.type}</div>
                                                    </div>
                                                </div>
                                            ))}
                                            {scanResults.ml_results.trackers.fingerprinting.map((f, i) => (
                                                <div key={`f-${i}`} className="tracker-item">
                                                    <div className="tracker-icon" style={{ background: '#fee2e2', color: '#ef4444' }}><Zap size={16} /></div>
                                                    <div className="tracker-info">
                                                        <div className="tracker-domain">{f.script}</div>
                                                        <div className="tracker-type">Fingerprinting</div>
                                                    </div>
                                                </div>
                                            ))}
                                            {scanResults.ml_results.trackers.totalTrackers === 0 &&
                                                scanResults.ml_results.trackers.totalFingerprinting === 0 && (
                                                    <div className="audit-item">
                                                        <div className="audit-icon icon-emerald"><Shield size={20} /></div>
                                                        <div className="audit-info">
                                                            <div className="audit-name">No Trackers Detected</div>
                                                            <div className="audit-status">This site respects your privacy.</div>
                                                        </div>
                                                    </div>
                                                )}
                                        </div>
                                    )}
                                </section>
                            </div>
                        )}

                        {subView === 'history' && (
                            <div className="scroll-view">
                                <section className="results-section">
                                    <h3 className="section-title">Scan History</h3>
                                    {history.length === 0 ? (
                                        <div className="empty-state">No previous scans found.</div>
                                    ) : (
                                        <div className="audit-list">
                                            {history.map((h, i) => (
                                                <div key={i} className="history-item" onClick={() => {
                                                    setScanResults(h);
                                                    setSubView('audit');
                                                }}>
                                                    <div className="history-top">
                                                        <div className="history-url">{h.url}</div>
                                                        <div className="history-date">{new Date(h.timestamp).toLocaleDateString()}</div>
                                                    </div>
                                                    <div className="history-bottom">
                                                        <span className={`history-score ${h.ml_results.status_label.toLowerCase()}`}>
                                                            Score: {h.ml_results.risk_score}
                                                        </span>
                                                        <span className="text-muted">•</span>
                                                        <span>{h.ml_results.status_label}</span>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </section>
                            </div>
                        )}

                        <footer className="footer-links">
                            <div className="footer-item">
                                <span className="val">RF2.0</span>
                                <span className="lab">Model</span>
                            </div>
                            <div className="div" />
                            <div className="footer-item">
                                <span className="val">AI</span>
                                <span className="lab">Analysis</span>
                            </div>
                        </footer>
                    </motion.div>
                )}
                {view === 'settings' && (
                    <motion.div
                        className="settings-view"
                        initial={{ opacity: 0, x: 50 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -50 }}
                        transition={{ duration: 0.3 }}
                    >
                        <header className="header">
                            <div className="brand" onClick={() => setView('dashboard')} style={{ cursor: 'pointer' }}>
                                <ChevronRight style={{ transform: 'rotate(180deg)' }} size={20} />
                                <span>Settings</span>
                            </div>
                        </header>

                        <div className="settings-content">
                            <div className="settings-group">
                                <h4 className="group-label">Scan Preferences</h4>
                                <div className="setting-item">
                                    <div className="setting-info">
                                        <div className="setting-name">Default Scan Profile</div>
                                        <div className="setting-desc">Primary analysis mode for new scans</div>
                                    </div>
                                    <select
                                        className="setting-select"
                                        value={settings.defaultScanType}
                                        onChange={(e) => updateSetting('defaultScanType', e.target.value)}
                                    >
                                        <option value="quick">Quick Scan</option>
                                        <option value="full">Full Security Audit</option>
                                    </select>
                                </div>

                                <div className="setting-item">
                                    <div className="setting-info">
                                        <div className="setting-name">Auto-Protection</div>
                                        <div className="setting-desc">Automatically scan tabs on change</div>
                                    </div>
                                    <div
                                        className={`toggle ${settings.autoScan ? 'active' : ''}`}
                                        onClick={() => updateSetting('autoScan', !settings.autoScan)}
                                    >
                                        <div className="toggle-thumb" />
                                    </div>
                                </div>
                            </div>

                            <div className="settings-group">
                                <h4 className="group-label">System</h4>
                                <div className="setting-item">
                                    <div className="setting-info">
                                        <div className="setting-name">Critical Alerts</div>
                                        <div className="setting-desc">Notify on high-risk detections</div>
                                    </div>
                                    <div
                                        className={`toggle ${settings.notifications ? 'active' : ''}`}
                                        onClick={() => updateSetting('notifications', !settings.notifications)}
                                    >
                                        <div className="toggle-thumb" />
                                    </div>
                                </div>

                                <div className="setting-item">
                                    <div className="setting-info">
                                        <div className="setting-name">Theme Engine</div>
                                        <div className="setting-desc">Switch between Light and Dark interface</div>
                                    </div>
                                    <button
                                        className="btn btn-secondary btn-small"
                                        onClick={() => updateSetting('theme', settings.theme === 'dark' ? 'light' : 'dark')}
                                    >
                                        {settings.theme.toUpperCase()}
                                    </button>
                                </div>
                            </div>

                            <div className="settings-group" style={{ marginTop: '20px' }}>
                                <h4 className="group-label">Trusted Whitelist</h4>
                                <div className="setting-desc">Domains excluded from automatic scanning</div>

                                <div className="whitelist-items">
                                    {whitelist.map((domain, i) => (
                                        <div key={i} className="whitelist-item">
                                            <span className="whitelist-domain">{domain}</span>
                                            <Zap
                                                size={14}
                                                className="remove-whitelist"
                                                onClick={() => removeFromWhitelist(domain)}
                                            />
                                        </div>
                                    ))}
                                    {whitelist.length === 0 && <div className="text-muted" style={{ fontSize: '12px' }}>No domains whitelisted.</div>}
                                </div>

                                <div className="add-whitelist-box">
                                    <input
                                        className="whitelist-input"
                                        placeholder="e.g. google.com"
                                        value={newWhitelistDomain}
                                        onChange={(e) => setNewWhitelistDomain(e.target.value)}
                                    />
                                    <button className="btn btn-primary btn-add" onClick={addToWhitelist}>Add</button>
                                </div>
                            </div>

                            <div className="settings-footer">
                                <p>WebGuard Engine v3.3.0</p>
                                <p>AI Intelligence: Active</p>
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            <AnimatePresence>
                {isScanning && (
                    <motion.div
                        className="scan-overlay"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                    >
                        <div className="scan-content">
                            <motion.h3
                                animate={{ opacity: [0.5, 1, 0.5] }}
                                transition={{ repeat: Infinity, duration: 2 }}
                            >
                                Analyzing Security Matrix...
                            </motion.h3>
                            <div className="progress-container">
                                <motion.div
                                    className="progress-bar"
                                    initial={{ width: 0 }}
                                    animate={{ width: `${progress}%` }}
                                />
                            </div>
                            <p>Identifying loopholes with Random Forest ML</p>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div >
    );
}

export default App;
