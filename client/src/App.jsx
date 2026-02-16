import { useState, useEffect } from 'react';
import { Shield, Zap, Activity, Download, Settings, ChevronRight, AlertTriangle, CheckCircle, FileText } from 'lucide-react';
import axios from 'axios';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { motion, AnimatePresence } from 'framer-motion';
import './App.css';

const API_BASE = 'http://localhost:5000/api';

function App() {
    const [view, setView] = useState('dashboard');
    const [scanResults, setScanResults] = useState(null);
    const [isScanning, setIsScanning] = useState(false);
    const [progress, setProgress] = useState(0);
    const [monitoringActive, setMonitoringActive] = useState(true);
    const [gaugeKey, setGaugeKey] = useState(0);

    const restartGaugeAnimation = () => setGaugeKey(prev => prev + 1);

    const startScan = async (type = 'full') => {
        setIsScanning(true);
        setProgress(10);

        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            const response = await axios.post(`${API_BASE}/scan`, { url: tab.url });

            setProgress(100);
            setScanResults(response.data);

            setTimeout(() => setIsScanning(false), 500);
        } catch (error) {
            console.error('Scan failed:', error);
            setIsScanning(false);
            alert('Scan failed. Please ensure the backend services are running.');
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

            doc.text(`Safety Status:`, 15, 85);
            doc.setTextColor(statusColor[0], statusColor[1], statusColor[2]);
            doc.setFont(undefined, 'bold');
            doc.text(`${status}`, 45, 85);
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
                            >
                                <Settings className="settings-icon" size={20} />
                            </motion.div>
                        </header>

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
                                        scanResults.ml_results.status_label === 'VULNERABLE' ? 'Insecure Loophole' :
                                            scanResults.ml_results.status_label === 'SUSPICIOUS' ? 'Suspicious Activity' :
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
                                    className={`toggle ${monitoringActive ? 'active' : ''}`}
                                    onClick={() => setMonitoringActive(!monitoringActive)}
                                >
                                    <div className="toggle-thumb" />
                                </div>
                            </div>
                        </motion.section>

                        <section className="results-section">
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
        </div>
    );
}

export default App;
