const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');
require('dotenv').config(); // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 3000;

// Keep your Google Script URL hidden using Environment Variables
const GOOGLE_SCRIPT_URL = process.env.GOOGLE_SCRIPT_URL;

if (!GOOGLE_SCRIPT_URL) {
    console.error("FATAL ERROR: GOOGLE_SCRIPT_URL is not defined in .env file.");
    process.exit(1);
}

// 1. Core Security Headers (Prevents XSS, Clickjacking, etc.)
app.use(helmet());
app.use(cors());

// Middleware to parse incoming form data (URL Encoded or JSON)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// 2. Anti-Scraper Middleware (Blocks common bot User-Agents)
const blockScrapers = (req, res, next) => {
    const userAgent = req.headers['user-agent'] || '';
    const blockedAgents = [
        'python-requests', 'scrapy', 'curl', 'wget', 'postman', 
        'bot', 'crawl', 'spider', 'slurp', 'ia_archiver'
    ];

    const isBot = blockedAgents.some(bot => userAgent.toLowerCase().includes(bot));
    
    if (isBot) {
        console.warn(`[SECURITY] Blocked suspected bot/scraper. IP: ${req.ip}, UA: ${userAgent}`);
        // Return a generic 403 Forbidden to discourage the bot
        return res.status(403).send('Forbidden: Access Denied.');
    }
    next();
};

// Apply scraper blocking to all routes
app.use(blockScrapers);

// 3. Global Rate Limiter (Prevents aggressive scraping of the HTML page)
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(globalLimiter);

// 4. Strict Rate Limiter for the API/Form Submission (Prevents Form Spam)
const apiLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour window
    max: 5, // Limit each IP to 5 form submissions per hour
    message: JSON.stringify({ error: 'Too many form submissions. Please try again later.' })
});

// Serve the static HTML file
app.use(express.static(path.join(__dirname, 'public')));

// 5. Secure Backend Proxy for Form Submission
// This hides the Google Script URL and performs server-side validation
app.post('/api/submit', apiLimiter, async (req, res) => {
    try {
        // --- HONEYPOT VALIDATION ---
        // Bots will automatically fill out all fields. Humans won't see this hidden field.
        if (req.body['bot-check'] && req.body['bot-check'].length > 0) {
            console.warn(`[SECURITY] Honeypot triggered by IP: ${req.ip}`);
            // Fake a success response to confuse the bot
            return res.status(200).json({ result: 'success', note: 'bot trapped' });
        }

        // Construct FormData to send to Google Apps Script
        const formData = new URLSearchParams();
        for (const key in req.body) {
            // Don't send the honeypot field to Google Sheets
            if (key !== 'bot-check') {
                formData.append(key, req.body[key]);
            }
        }

        // Send data to the hidden Google Apps Script URL via server-side fetch
        // Node 18+ has built-in fetch. For older versions, require('node-fetch').
        const response = await fetch(GOOGLE_SCRIPT_URL, {
            method: 'POST',
            body: formData,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const data = await response.json();
        
        if (data.result === 'success') {
            res.status(200).json(data);
        } else {
            res.status(500).json({ error: 'Failed to process submission via upstream server.' });
        }

    } catch (error) {
        console.error(`[ERROR] Form submission proxy failed:`, error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.listen(PORT, () => {
    console.log(`Secure Server running on port ${PORT}`);
    console.log(`Scraper protection, Rate Limiting, and Proxied Submissions are ACTIVE.`);
});