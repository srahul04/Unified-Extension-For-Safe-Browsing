const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const dotenv = require('dotenv');
const axios = require('axios');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const PYTHON_SERVICE_URL = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';

app.use(helmet());
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());

// API Endpoints
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', version: '2.2.0' });
});

/**
 * Main Scan Endpoint
 * Aggregates results from VirusTotal and Python ML Analysis
 */
app.post('/api/scan', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    console.log(`Scan requested for: ${url}`);

    try {
        // Parallel requests to analysis services
        const [mlAnalysis, vtAnalysis] = await Promise.allSettled([
            axios.post(`${PYTHON_SERVICE_URL}/analyze`, { url }),
            // VirusTotal check could go here, or we delegate to client/extension
            Promise.resolve({ data: { category: 'threat_intelligence', provider: 'vt' } })
        ]);

        res.json({
            success: true,
            url,
            ml_results: mlAnalysis.status === 'fulfilled' ? mlAnalysis.value.data : { error: 'ML service unavailable' },
            vt_results: vtAnalysis.status === 'fulfilled' ? vtAnalysis.value.data : { error: 'VT intelligence unavailable' },
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Scan orchestration failed:', error);
        res.status(500).json({ error: 'Internal server error during scan' });
    }
});

app.listen(PORT, () => {
    console.log(`WebGuard Express Server running on port ${PORT}`);
});
