# Website Security Scanner v2.0 - Quick Start Guide

## Installation

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right corner)
3. Click **Load unpacked**
4. Select the folder: `d:\Unified-Extension-For-Safe-Browsing`
5. The extension icon 🛡️ should appear in your toolbar

## First Scan

1. **Visit any website** (e.g., https://google.com)
2. **Click the extension icon** 🛡️
3. **Click "Start Security Scan"** (all checks are pre-selected)
4. **Wait 3-5 seconds** for the scan to complete
5. **View your security grade** (A-F) and detailed results

## Features to Try

### 🎯 Security Grading
- Look for the **score dashboard** at the top of results
- See your **Overall, Security, and Privacy** grades
- Grades range from A (excellent) to F (poor)

### 🌙 Dark Mode
- Click the **moon icon** (🌙) in the header
- Theme preference is saved automatically

### 📊 Scan History
- Click the **chart icon** (📊) to view recent scans
- Compare scores over time
- See up to 50 previous scans

### 💾 Export Results
- Click the **save icon** (💾) after a scan
- Choose format:
  - **1** = JSON (full data)
  - **2** = CSV (spreadsheet)
  - **3** = HTML (standalone report)
- Or use **PDF Report** button for professional PDF

### 🔍 Security Checks

**Phishing Detection** 🎣
- Detects suspicious URLs
- Checks for IP addresses, suspicious TLDs
- Risk score 0-100

**Malware Detection** 🦠
- Checks against known malware domains
- Critical alerts for dangerous sites

**HTTPS/SSL** 🔒
- Verifies encrypted connections
- Warns about HTTP sites

**Security Headers** 🛡️
- Checks 7 critical headers
- Identifies missing protections

**Cookie Security** 🍪
- Analyzes cookie flags
- Detects insecure cookies

**Mixed Content** ⚠️
- Finds HTTP resources on HTTPS pages
- Flags high-risk scripts/iframes

**Traffic Analysis** 🚦
- Counts network requests
- Shows data transferred

**Privacy Analysis** 🔐
- Detects trackers (Google Analytics, Facebook, etc.)
- Finds fingerprinting attempts
- Calculates privacy score

## Testing Different Sites

### Test HTTPS Detection
- Visit: `http://example.com` (should show critical warning)
- Visit: `https://google.com` (should show success)

### Test Tracker Detection
- Visit: `https://cnn.com` (many trackers)
- Visit: `https://duckduckgo.com` (minimal tracking)

### Test Phishing Detection
- Try URLs with suspicious patterns
- Look for risk score in results

## Troubleshooting

**Extension not loading?**
- Check Chrome version (requires Chrome 88+)
- Verify all files are in the folder
- Check browser console for errors

**Scan fails?**
- Refresh the page and try again
- Some sites may block extension access
- Check if site allows content scripts

**No results showing?**
- Wait for scan to complete (3-5 seconds)
- Check if any checks are selected
- Try reloading the extension

## Understanding Results

### Severity Levels
- 🔴 **Critical** - Immediate action required
- 🟡 **Warning** - Should be addressed
- 🔵 **Info** - Informational
- 🟢 **Success** - All good

### Security Grades
- **A (90-100)** - Excellent security
- **B (80-89)** - Good security
- **C (70-79)** - Fair security
- **D (60-69)** - Poor security
- **F (0-59)** - Very poor security

## Advanced Usage

### Custom Scans
- Uncheck boxes to skip certain checks
- Use "Select All" / "Deselect All" button
- Faster scans with fewer checks

### Comparing Scans
- Run scan on same site multiple times
- Check scan history to see improvements
- Export results for record-keeping

### Privacy Mode
- Enable dark mode for better privacy
- Export results as JSON for analysis
- Review tracker list in privacy check

## Support

For issues or questions:
- Check the walkthrough document
- Review implementation plan
- Check browser console for errors

---

**Version**: 2.0.0  
**Last Updated**: December 2025
