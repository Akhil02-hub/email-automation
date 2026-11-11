require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const { google } = require('googleapis');
const cron = require('node-cron');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');

const BUSINESS_TYPE = (process.env.BUSINESS_TYPE || 'general').toLowerCase();
const BUSINESS_NAME = String(process.env.BUSINESS_NAME || 'Your Business').trim();

const app = express();

// 1. SECURITY HEADERS
app.use(helmet({
    contentSecurityPolicy: {
        useDefaults: true,
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            frameSrc: ["'self'"],
            connectSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

app.set('trust proxy', 1);

// 2. CORS
const allowedOrigins = (process.env.FRONTEND_URL ? process.env.FRONTEND_URL.split(',') : ['http://localhost:3000']).map(o => o.trim()).filter(Boolean);
app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            return callback(new Error('The CORS policy for this site does not allow access from the specified Origin.'), false);
        }
        return callback(null, true);
    },
    credentials: true
}));
// CORS error handler moved to bottom of file
if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_REFRESH_TOKEN) {
    console.error("Missing Google OAuth env vars. Email sending will fail.");
}
if (!process.env.GMAIL_SENDER || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(process.env.GMAIL_SENDER)) {
    console.error('FATAL: GMAIL_SENDER must be a real, authorized address (e.g. your-email@gmail.com). Refusing to start.');
    process.exit(1);
}
if (process.env.REPLY_TO && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(process.env.REPLY_TO)) {
    console.error('FATAL: REPLY_TO must be a valid email address. Refusing to start.');
    process.exit(1);
}
if (!process.env.UNSUBSCRIBE_SECRET) {
    console.warn('[unsubscribe] UNSUBSCRIBE_SECRET not set — falling back to JWT_SECRET. Set a dedicated secret in production so the token cannot be guessed by anyone holding the JWT secret.');
}
if (!process.env.UNSUBSCRIBE_SECRET && !process.env.JWT_SECRET) {
    console.error('FATAL: at least one of UNSUBSCRIBE_SECRET / JWT_SECRET is required to sign unsubscribe tokens.');
    process.exit(1);
}
if (!process.env.SITE_URL) {
    console.error('FATAL: SITE_URL must be set (used in every email link).');
    process.exit(1);
}
if (!process.env.UNSUBSCRIBE_URL) {
    console.error('FATAL: UNSUBSCRIBE_URL must be set (required for List-Unsubscribe headers).');
    process.exit(1);
}
if (!['ecommerce', 'saas', 'finance', 'media', 'healthcare', 'general'].includes(BUSINESS_TYPE)) {
    console.error('FATAL: BUSINESS_TYPE must be one of: ecommerce | saas | finance | media | healthcare | general');
    process.exit(1);
}
console.log('[business] BUSINESS_TYPE=' + BUSINESS_TYPE + ' · BUSINESS_NAME=' + BUSINESS_NAME);

app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());

// CSRF guard: mutating requests must carry X-Requested-With: fetch.
// Browsers cannot send that header cross-origin without a CORS preflight,
// which the cors() config above does not allow for untrusted origins.
// Webhooks + sync skip this because they use X-API-Key. Login skips because
// there is no cookie yet.
app.use((req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    if (req.path.startsWith('/api/webhooks/')) return next();
    if (req.path === '/api/admin/email-automation/sync') return next();
    // External cron wake-up: /run accepts an X-API-Key from an outside pinger
    // (cron-job.org etc.). Exempt that path only when the header is present,
    // so cookie-authenticated browser calls still require X-Requested-With.
    if (req.path === '/api/admin/email-automation/run' && req.get('X-API-Key')) return next();
    if (req.path === '/api/auth/login') return next();
    // RFC 8058 one-click unsubscribe — Gmail/Apple Mail/Outlook POST here with
    // no custom headers. The URL itself carries an HMAC token, so CSRF abuse
    // is already impossible; exempting the path restores one-click opt-out.
    if (req.path === '/unsubscribe') return next();
    if (req.get('X-Requested-With') !== 'fetch') {
        return res.status(403).json({ error: 'Missing X-Requested-With header.' });
    }
    next();
});
app.use(express.static(require('path').join(__dirname, 'public'), { dotfiles: 'deny', index: false }));
app.get('/', (req, res) => {
    res.set('Cache-Control', 'no-store');
    const path = require('path');
    const fs = require('fs');
    const publicPath = path.join(__dirname, 'public', 'email_automation.html');
    const rootPath = path.join(__dirname, 'email_automation.html');
    res.sendFile(fs.existsSync(publicPath) ? publicPath : rootPath);
});

// ==========================================
// 1. NEON POSTGRES DATABASE SETUP
// ==========================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }, // Required for Neon
    max: Number(process.env.PG_POOL_MAX || 5),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

pool.query('SELECT 1').then(async () => {
    console.log('Connected to Neon PostgreSQL successfully.');
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS settings (
                id SERIAL PRIMARY KEY, 
                workflows TEXT, 
                templates TEXT
            );
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY, 
                recipient TEXT, 
                template TEXT, 
                status TEXT, 
                detail TEXT, 
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS email_queue (
                id SERIAL PRIMARY KEY,
                recipient TEXT,
                template_id TEXT,
                context JSONB,
                related_id TEXT,
                scheduled_at TIMESTAMP,
                status TEXT DEFAULT 'pending',
                attempts INTEGER DEFAULT 0,
                last_error TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS context JSONB;
            ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS related_id TEXT;
            ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS processing_started_at TIMESTAMP;
            ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
            CREATE UNIQUE INDEX IF NOT EXISTS email_queue_dedup
                ON email_queue (template_id, related_id)
                WHERE related_id IS NOT NULL;
            CREATE TABLE IF NOT EXISTS suppressions (
                email TEXT PRIMARY KEY,
                reason TEXT,
                scope TEXT DEFAULT 'marketing',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            ALTER TABLE suppressions ADD COLUMN IF NOT EXISTS scope TEXT DEFAULT 'marketing';

            CREATE INDEX IF NOT EXISTS logs_created_at_idx      ON logs (created_at DESC);
            CREATE INDEX IF NOT EXISTS email_queue_claim_idx    ON email_queue (status, scheduled_at) WHERE status = 'pending';
            CREATE INDEX IF NOT EXISTS email_queue_proc_idx     ON email_queue (status, processing_started_at) WHERE status = 'processing';
            CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT);
        `);
    } catch (err) {
        console.error("Table creation error:", err);
    }
}).catch(err => {
    console.error('FATAL: Database connection error:', err.message);
    process.exit(1);
});

// Best-effort: add columns to user_orders if the table exists in this DB
pool.query(`ALTER TABLE user_orders ADD COLUMN IF NOT EXISTS payment_status TEXT`)
    .catch(err => { if (!/does not exist|relation/i.test(err.message)) console.error('user_orders ALTER error:', err.message); });
pool.query(`ALTER TABLE user_orders ADD COLUMN IF NOT EXISTS paid_at TIMESTAMP`)
    .catch(err => { if (!/does not exist|relation/i.test(err.message)) console.error('user_orders ALTER error:', err.message); });
pool.query(`ALTER TABLE user_orders ADD COLUMN IF NOT EXISTS payment_reference TEXT`)
    .catch(err => { if (!/does not exist|relation/i.test(err.message)) console.warn('payment_reference ALTER:', err.message); });
pool.query(`ALTER TABLE user_orders ADD COLUMN IF NOT EXISTS transaction_id TEXT`)
    .catch(err => { if (!/does not exist|relation/i.test(err.message)) console.warn('transaction_id ALTER:', err.message); });
pool.query(`ALTER TABLE user_orders ADD COLUMN IF NOT EXISTS event_date DATE`)
    .catch(err => { if (!/does not exist|relation/i.test(err.message) && !/already exists/i.test(err.message)) console.warn('event_date ALTER:', err.message); });
pool.query(
    `SELECT data_type FROM information_schema.columns
     WHERE table_name = 'user_orders' AND column_name = 'event_date'`
).then(r => {
    if (r.rows[0] && r.rows[0].data_type !== 'date') {
        // The Python admin backend creates this column as TEXT. Coercion-safe
        // queries below handle both TEXT and DATE, so we warn instead of exiting.
        console.warn('[schema] user_orders.event_date is ' + r.rows[0].data_type +
            ' — event reminder queries are coercion-safe, but consider migrating to DATE.');
    }
}).catch(() => { });
pool.query(`ALTER TABLE user_orders ADD COLUMN IF NOT EXISTS delivery_date TIMESTAMP`)
    .catch(err => { if (!/does not exist|relation/i.test(err.message) && !/already exists/i.test(err.message)) console.warn('delivery_date ALTER:', err.message); });
pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS marketing_consent BOOLEAN DEFAULT false`)
    .catch(err => { if (!/does not exist|relation/i.test(err.message)) console.warn('users ALTER:', err.message); });
pool.query(`ALTER TABLE users ALTER COLUMN marketing_consent SET DEFAULT false`)
    .catch(err => { if (!/does not exist|relation/i.test(err.message)) console.warn('users.marketing_consent default:', err.message); });
pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS birthday DATE`)
    .catch(err => { if (!/does not exist|relation/i.test(err.message)) console.warn('users.birthday ALTER:', err.message); });


// ==========================================
// 2. EMAIL TRANSPORTER
// ==========================================
const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    'https://developers.google.com/oauthplayground'
);

oauth2Client.setCredentials({
    refresh_token: process.env.GOOGLE_REFRESH_TOKEN
});

const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

// ─────────────────────────────────────────────────────────────────────────
// TRANSPORT: Gmail OAuth 2.0 REST API ONLY. NO SMTP. NO PASSWORDS.
// If you ever see "getaddrinfo ENOTFOUND smtp.gmail.com" (or "smpt.gmail.com")
// in these logs, you are running an OLD version of this file that still used
// nodemailer/SMTP. Redeploy this file — it cannot produce that error.
// ─────────────────────────────────────────────────────────────────────────
console.log('[email-transport] Gmail OAuth 2.0 REST API only — SMTP is not used anywhere in this file.');

(async () => {
    try {
        const { credentials } = await oauth2Client.refreshAccessToken();
        if (!credentials || !credentials.access_token) {
            throw new Error('OAuth refresh returned no access_token.');
        }
        oauth2Client.setCredentials(credentials);
        console.log('[email-transport] GOOGLE_REFRESH_TOKEN is valid — access token acquired.');
    } catch (err) {
        console.error('[email-transport] GOOGLE_REFRESH_TOKEN is INVALID — email sending will fail. ' + (err && err.message ? err.message : err));
        console.error('[email-transport] Regenerate at https://developers.google.com/oauthplayground with scope https://mail.google.com/ and update GOOGLE_REFRESH_TOKEN.');
    }
})();

// --- Template substitution helpers ---
function substituteHtml(text, vars) {
    if (!text) return '';
    return String(text).replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (m, k) => {
        if (!Object.prototype.hasOwnProperty.call(vars || {}, k)) return '';
        return String(vars[k] ?? '').replace(/[&<>"']/g, c =>
            ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    });
}
function substituteText(text, vars) {
    if (!text) return '';
    return String(text).replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (m, k) => {
        if (!Object.prototype.hasOwnProperty.call(vars || {}, k)) return '';
        return String(vars[k] ?? '');
    });
}
function plainTextToHtml(text) {
    if (!text) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\r\n/g, '\n')
        .split(/\n{2,}/)
        .map(p => '<p style="margin:0 0 12px">' + p.replace(/\n/g, '<br>') + '</p>')
        .join('');
}

function classifyGmailError(rawMessage) {
    const m = String(rawMessage || '');
    if (/ENOTFOUND|ECONNREFUSED|ETIMEDOUT/i.test(m) && /smtp/i.test(m)) {
        return 'FATAL: Your deployed server is still using SMTP (' + m + '). Redeploy this OAuth-only file — no SMTP code exists in the current version.';
    }
    if (/ENOTFOUND|ECONNREFUSED|ETIMEDOUT/i.test(m) && /gmail\.googleapis\.com/i.test(m)) {
        return 'Network error reaching gmail.googleapis.com — check your host’s outbound HTTPS / DNS (' + m + ').';
    }
    if (/invalid_grant/i.test(m)) {
        return 'GOOGLE_REFRESH_TOKEN is expired or was revoked. Regenerate at https://developers.google.com/oauthplayground (scope: https://mail.google.com/) and update the env var.';
    }
    if (/invalid_client/i.test(m)) {
        return 'GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET is wrong. Check Render/Env vars.';
    }
    if (/unauthorized_client|access_denied/i.test(m)) {
        return 'OAuth client is not authorized for Gmail sending. Verify the OAuth consent screen and that scope https://mail.google.com/ is granted.';
    }
    if (/Gmail API timeout/i.test(m)) {
        return 'Gmail API did not respond within 30s. The message may still have been delivered — check the Gmail account’s Sent folder before retrying.';
    }
    return m || 'Unknown Gmail API error';
}

// HMAC that protects /unsubscribe from CSRF-style opt-out attacks. An attacker
// who embeds <img src="/unsubscribe?email=victim"> cannot forge the token, so
// the suppression is refused.
function unsubToken(email) {
    const crypto = require('crypto');
    const secret = process.env.UNSUBSCRIBE_SECRET || process.env.JWT_SECRET;
    if (!secret) {
        throw new Error('UNSUBSCRIBE_SECRET (or JWT_SECRET) must be set to sign unsubscribe tokens.');
    }
    return crypto.createHmac('sha256', secret)
        .update(String(email).trim().toLowerCase())
        .digest('base64url');
}

async function sendEmail(to, subject, html, templateName, text, isMarketing = false) {
    const crypto = require('crypto');
    const senderEmail = process.env.GMAIL_SENDER;
    const senderName = String(process.env.GMAIL_SENDER_NAME || BUSINESS_NAME).replace(/[\r\n]/g, ' ');
    const replyTo = String(process.env.REPLY_TO || senderEmail).replace(/[\r\n]/g, '').trim();
    const unsubUrl = (process.env.UNSUBSCRIBE_URL || '')
        + '?email=' + encodeURIComponent(String(to).trim())
        + '&t=' + encodeURIComponent(unsubToken(to));
    const safeTo = String(to).replace(/[\r\n]/g, '').trim();
    const safeSubject = String(subject).replace(/[\r\n]/g, ' ').trim();
    const utf8Subject = `=?UTF-8?B?${Buffer.from(safeSubject, 'utf8').toString('base64')}?=`;
    const b64 = (str) => Buffer.from(String(str || ''), 'utf8')
        .toString('base64')
        .replace(/.{1,76}/g, '$&\r\n')
        .trim();
    const boundary = '----=_Part_' + crypto.randomUUID();
    const plainBody = text || String(html || '')
        .replace(/<style[\s\S]*?<\/style>/gi, '')
        .replace(/<script[\s\S]*?<\/script>/gi, '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
    const messageParts = [
        `From: ${senderName} <${senderEmail}>`,
        `To: ${safeTo}`,
        `Subject: ${utf8Subject}`,
        `Date: ${new Date().toUTCString()}`,
        `Message-ID: <${crypto.randomUUID()}@${(process.env.GMAIL_SENDER || 'localhost').split('@')[1] || 'localhost'}>`,
        `Reply-To: ${replyTo}`,
        ...(isMarketing ? [
            `List-Unsubscribe: <${unsubUrl}>`,
            `List-Unsubscribe-Post: List-Unsubscribe=One-Click`
        ] : []),
        `MIME-Version: 1.0`,
        `Content-Type: multipart/alternative; boundary="${boundary}"`,
        ``,
        `--${boundary}`,
        `Content-Type: text/plain; charset="UTF-8"`,
        `Content-Transfer-Encoding: base64`,
        ``,
        b64(plainBody),
        ``,
        `--${boundary}`,
        `Content-Type: text/html; charset="UTF-8"`,
        `Content-Transfer-Encoding: base64`,
        ``,
        b64(html || `<p>${plainBody}</p>`),
        ``,
        `--${boundary}--`,
        ``
    ];
    const message = messageParts.join('\r\n');
    const encodedMessage = Buffer.from(message)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    let _timeoutHandle = null;
    const _clearTimer = () => { if (_timeoutHandle) { clearTimeout(_timeoutHandle); _timeoutHandle = null; } };
    try {
        const apiRes = await Promise.race([
            gmail.users.messages.send({
                userId: 'me',
                requestBody: { raw: encodedMessage }
            }),
            new Promise((_, reject) => {
                _timeoutHandle = setTimeout(() => reject(new Error('Gmail API timeout (30s)')), 30000);
                if (typeof _timeoutHandle.unref === 'function') _timeoutHandle.unref();
            })
        ]);
        _clearTimer();
        try {
            await pool.query(
                `INSERT INTO logs (recipient, template, status, detail) VALUES ($1, $2, 'sent', $3)`,
                [to, templateName, 'Accepted by Gmail API · id=' + (apiRes.data.id || 'unknown')]
            );
        } catch (logErr) {
            console.error('Log insert failed after successful send:', logErr.message);
        }
        return { success: true, id: apiRes.data.id };
    } catch (error) {
        _clearTimer();
        const errMsg = classifyGmailError(error && error.message ? error.message : String(error));
        console.error('[gmail-oauth2] Send failed for ' + to + ' — ' + errMsg);
        try {
            await pool.query(
                `INSERT INTO logs (recipient, template, status, detail) VALUES ($1, $2, 'failed', $3)`,
                [to, templateName, errMsg]
            );
        } catch (_) { }
        return { success: false, error: errMsg };
    }
}

// ==========================================
// 3. RATE LIMITING (HIGH SECURITY)
// ==========================================
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100,
    message: { error: 'Too many requests, please slow down.' }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    handler: (req, res) => res.status(429).json({ error: 'Too many failed login attempts. Please wait 15 minutes.' }),
    message: { error: 'Too many login attempts.' }
});

function authenticateToken(req, res, next) {
    const token = req.cookies?.token;
    if (!token) return res.status(401).json({ error: 'Access Denied. No token.' });
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(401).json({ error: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
}

// Accepts EITHER a valid admin JWT cookie (dashboard) OR an X-API-Key header
// matching AUTOMATION_API_KEY (external cron pinger). Used by /run so a
// cron-job.org / UptimeRobot job can wake Render and drain the queue on a
// schedule without holding a login session.
function authenticateTokenOrApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (apiKey && process.env.AUTOMATION_API_KEY) {
        const crypto = require('crypto');
        const expected = Buffer.from(String(process.env.AUTOMATION_API_KEY));
        const supplied = Buffer.from(String(apiKey));
        if (supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected)) {
            req.user = { role: 'api-key', source: 'external-cron' };
            return next();
        }
    }
    return authenticateToken(req, res, next);
}

app.post('/api/auth/login', loginLimiter, (req, res) => {
    try {
        const { password } = req.body;

        // Check if variables exist before crashing
        if (!process.env.DASHBOARD_PASSWORD_HASH) {
            return res.status(500).json({ error: "Server missing DASHBOARD_PASSWORD_HASH in Render settings." });
        }
        if (!/^\$2[ayb]\$/.test(process.env.DASHBOARD_PASSWORD_HASH)) {
            return res.status(500).json({ error: "DASHBOARD_PASSWORD_HASH is invalid. You pasted the raw password, not the bcrypt hash." });
        }
        if (!process.env.JWT_SECRET) {
            return res.status(500).json({ error: "Server missing JWT_SECRET in Render settings." });
        }

        const isMatch = bcrypt.compareSync(password, process.env.DASHBOARD_PASSWORD_HASH);
        if (isMatch) {
            const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '8h' });
            const crossSite = String(process.env.CROSS_SITE_COOKIES || '').toLowerCase() === 'true';
            res.cookie('token', token, {
                httpOnly: true,
                secure: crossSite ? true : (process.env.NODE_ENV === 'production'),
                sameSite: crossSite ? 'None' : 'Lax'
            });
            res.json({ success: true, message: 'Logged in securely.' });
        } else {
            res.status(401).json({ error: 'Incorrect password' });
        }
    } catch (error) {
        console.error("Login Crash:", error);
        res.status(500).json({ error: "Server crashed: " + error.message });
    }
});

// ==========================================
// 4. API ROUTES (No Login Required)
// ==========================================
app.post('/api/auth/logout', (req, res) => {
    const crossSite = String(process.env.CROSS_SITE_COOKIES || '').toLowerCase() === 'true';
    res.clearCookie('token', {
        httpOnly: true,
        secure: crossSite ? true : (process.env.NODE_ENV === 'production'),
        sameSite: crossSite ? 'None' : 'Lax'
    });
    res.json({ success: true, message: 'Logged out.' });
});

async function handleUnsub(req, res) {
    const crypto = require('crypto');
    const raw = (req.query.email || (req.body && req.body.email) || '').toString().trim().toLowerCase();
    const token = (req.query.t || (req.body && req.body.t) || '').toString();
    if (!raw) return res.status(400).send('Missing email parameter.');
    if (!/^[^\s,;<>]+@[^\s,;<>]+\.[^\s,;<>]+$/.test(raw)) return res.status(400).send('Invalid email parameter.');
    let expected;
    try {
        expected = unsubToken(raw);
    } catch (e) {
        return res.status(503).send('Unsubscribe is not configured on the server.');
    }
    const ok = token.length === expected.length &&
        crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected));
    if (!ok) return res.status(403).send('Invalid or missing unsubscribe token.');
    try {
        await pool.query(
            `INSERT INTO suppressions (email, reason, scope) VALUES ($1, 'user_unsubscribe', 'marketing')
             ON CONFLICT (email) DO UPDATE
                SET reason = EXCLUDED.reason,
                    scope  = CASE WHEN suppressions.scope = 'all' THEN 'all'
                                  ELSE EXCLUDED.scope END`,
            [raw]
        );
        if (req.method === 'POST') return res.status(200).send('OK');
        const safeRaw = String(raw).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
        res.send('<html><body style="font-family:sans-serif;text-align:center;padding:40px"><h2>Unsubscribed</h2><p>' + safeRaw + ' has been removed from marketing emails.</p></body></html>');
    } catch (e) {
        res.status(500).send('Could not process unsubscribe: ' + e.message);
    }
}
app.get('/unsubscribe', handleUnsub);
app.post('/unsubscribe', handleUnsub);
// Liveness probe — public so external monitors can reach it without a cookie,
// but it also reports whether *this specific request* carried a valid admin
// JWT. The dashboard uses `authenticated` to decide between showing the login
// form and the dashboard, without generating 401s on every fresh tab.
// Rate-limited + DB-liveness cached to protect the small Neon connection pool.
const healthLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,                         // 2 req/sec/IP — plenty for monitors + dashboard
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => res.status(429).json({ status: 'rate_limited', authenticated: false })
});
let _healthCache = { at: 0, ok: false };
app.get('/api/health', healthLimiter, async (req, res) => {
    let authenticated = false;
    const token = req.cookies?.token;
    if (token && process.env.JWT_SECRET) {
        try { jwt.verify(token, process.env.JWT_SECRET); authenticated = true; }
        catch (_) { /* expired or invalid token — authenticated stays false */ }
    }
    const now = Date.now();
    // Cache only the DB liveness bit for 2 s; `authenticated` is recomputed
    // for every request so it stays accurate.
    if (now - _healthCache.at > 2000) {
        try {
            await pool.query('SELECT 1');
            _healthCache = { at: now, ok: true };
        } catch (_) {
            _healthCache = { at: now, ok: false };
        }
    }
    if (_healthCache.ok) {
        res.json({ status: 'ok', authenticated, version: '1.0.0' });
    } else {
        res.status(503).json({ status: 'degraded', authenticated, error: 'database_unreachable' });
    }
});

// Authenticated version — kept for external monitors and for the
// dashboard's explicit "Test connection" button.
app.get('/api/admin/email-automation/health', authenticateToken, async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok', db: 'connected', version: '1.0.0' });
    } catch (e) {
        res.status(503).json({ status: 'degraded', db: 'disconnected', error: e.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────
// Gmail OAuth health check — proves the refresh token + client ID/secret work,
// and that outbound HTTPS to gmail.googleapis.com is reachable.
// If this returns OK but you still see "getaddrinfo ENOTFOUND smpt.gmail.com",
// the error is coming from an OLD version of your deployment (nodemailer/SMTP).
// ─────────────────────────────────────────────────────────────────────────
app.get('/api/admin/email-automation/gmail-check', authenticateToken, async (req, res) => {
    try {
        const { credentials } = await oauth2Client.refreshAccessToken();
        if (!credentials || !credentials.access_token) {
            return res.status(503).json({
                ok: false,
                transport: 'gmail-oauth2',
                error: 'OAuth refresh returned no access token.',
                hint: 'Check GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN on the host.'
            });
        }
        oauth2Client.setCredentials(credentials);
        const profile = await gmail.users.getProfile({ userId: 'me' });
        res.json({
            ok: true,
            transport: 'gmail-oauth2',
            smtpUsed: false,
            sender: process.env.GMAIL_SENDER || null,
            gmailAccount: profile.data.emailAddress || null,
            messagesTotal: profile.data.messagesTotal ?? null,
            note: 'Emails are sent via the Gmail REST API over HTTPS. No SMTP is used anywhere in this server.'
        });
    } catch (e) {
        res.status(503).json({
            ok: false,
            transport: 'gmail-oauth2',
            smtpUsed: false,
            error: classifyGmailError(e && e.message ? e.message : String(e))
        });
    }
});

app.get('/api/admin/email-automation/setup', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query(`SELECT value FROM app_config WHERE key = 'setup'`);
        if (r.rows.length > 0 && r.rows[0].value) {
            const parsed = JSON.parse(r.rows[0].value);
            res.json({ configured: true, businessType: parsed.businessType, businessName: parsed.businessName });
        } else {
            res.json({ configured: false });
        }
    } catch (e) {
        res.json({ configured: false });
    }
});

app.post('/api/admin/email-automation/setup', authenticateToken, async (req, res) => {
    const { businessType, businessName } = req.body;
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT);
            INSERT INTO app_config (key, value) VALUES ('setup', $1)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
        `, [JSON.stringify({ businessType, businessName })]);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/admin/email-automation/templates', authenticateToken, async (req, res) => {
    try {
        const templates = await loadTemplates();
        res.json(templates);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/email-automation/overview', authenticateToken, async (req, res) => {
    const countOrZero = async (sql) => {
        try { const r = await pool.query(sql); return parseInt(r.rows[0].count) || 0; }
        catch (_) { return 0; }
    };
    try {
        const [emails, queued, customers, orders, payments] = await Promise.all([
            countOrZero(`SELECT COUNT(*) FROM logs`),
            countOrZero(`SELECT COUNT(*) FROM email_queue`),
            countOrZero(`SELECT COUNT(*) FROM users`),
            countOrZero(`SELECT COUNT(*) FROM user_orders`),
            countOrZero(`SELECT COUNT(*) FROM user_orders
                WHERE price IS NOT NULL
                  AND price::text <> 'Pending Quote'
                  AND price::text <> ''
                  AND LOWER(COALESCE(payment_status, '')) IN ('paid','confirmed','success','succeeded','completed')`)
        ]);
        res.json({ counts: { emails, queued, customers, orders, payments } });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/email-automation/logs', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, recipient, template, status, detail, created_at
               FROM logs
               ORDER BY created_at DESC
               LIMIT 100`
        );
        res.json(result.rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/email-automation/settings', authenticateToken, async (req, res) => {
    const { workflows, templates } = req.body;
    // Separate save paths: Templates save sends only `templates`, Workflows save
    // sends only `workflows`. Absent array means "leave that side unchanged" —
    // prevents a template edit from silently publishing stale localStorage
    // workflows and mass-requeuing previously-paused marketing jobs.
    const publishWorkflows = Array.isArray(workflows);
    const publishTemplates = Array.isArray(templates);
    if (!publishWorkflows && !publishTemplates) {
        return res.status(400).json({ error: 'Body must include workflows and/or templates.' });
    }
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const prevRes = await client.query(`SELECT workflows, templates FROM settings WHERE id != 99 ORDER BY id DESC LIMIT 1`);
        const prevRow = prevRes.rows[0] || {};
        const prevEnabled = {};
        try {
            const parsed = prevRow.workflows ? JSON.parse(prevRow.workflows) : [];
            if (Array.isArray(parsed)) parsed.forEach(w => { prevEnabled[w.id] = !!w.enabled; });
        } catch (_) { /* corrupt row — treat as all-off */ }

        const newlyEnabled = new Set();
        if (publishWorkflows) {
            workflows.forEach(w => {
                if (w && w.enabled && prevEnabled[w.id] === false) newlyEnabled.add(w.id);
            });
        }
        const workflowsToStore = publishWorkflows
            ? JSON.stringify(workflows)
            : (prevRow.workflows || JSON.stringify([]));
        const templatesToStore = publishTemplates
            ? JSON.stringify(templates)
            : (prevRow.templates || JSON.stringify([]));

        await client.query(`DELETE FROM settings WHERE id != 99`);
        await client.query(`INSERT INTO settings (workflows, templates) VALUES ($1, $2)`, [workflowsToStore, templatesToStore]);

        let requeueCount = 0;
        if (publishWorkflows && newlyEnabled.size > 0) {
            const newlyEnabledTemplates = ALL_TEMPLATE_IDS.filter(t => newlyEnabled.has(templateWorkflowId(t)));
            if (newlyEnabledTemplates.length > 0) {
                const requeue = await client.query(
                    `UPDATE email_queue
                        SET status = 'pending', last_error = NULL
                      WHERE status = 'skipped'
                        AND last_error = 'workflow_disabled'
                        AND template_id = ANY($1::text[])
                        AND scheduled_at > NOW() - INTERVAL '3 days'`,
                    [newlyEnabledTemplates]
                );
                requeueCount = requeue.rowCount || 0;
            }
        }
        await client.query('COMMIT');
        res.json({ success: true, message: 'Settings saved.', requeued: requeueCount, workflowsPublished: publishWorkflows, templatesPublished: publishTemplates });
    } catch (e) {
        await client.query('ROLLBACK').catch(() => { });
        res.status(500).json({ error: e.message });
    } finally {
        client.release();
    }
});

app.post('/api/admin/email-automation/send-test', authenticateToken, async (req, res) => {
    const { to, subject, html, template_id, text } = req.body;
    if (!to || !/^[^\s,;<>]+@[^\s,;<>]+\.[^\s,;<>]+$/.test(to)) return res.status(400).json({ error: 'Invalid email' });
    const isMarketingTest = MARKETING_TEMPLATES.has(template_id);
    let warning = null;
    // Global suppression (scope='all') overrides every template class — including
    // transactional. Warn regardless of what template_id was requested.
    if (await isSuppressed(to, 'welcome')) {
        warning = 'This recipient has a GLOBAL suppression (scope=all). Test send proceeds as an admin override.';
    } else if (isMarketingTest && await isSuppressed(to, template_id)) {
        warning = 'This recipient has unsubscribed from marketing emails. Test send proceeds as an admin override — do not use this path to send real marketing mail.';
    }
    const result = await sendEmail(to, subject, html, `Test: ${template_id}`, text, isMarketingTest);
    if (result.success) res.json({ success: true, message: 'Test sent.', warning });
    else res.status(500).json({ error: result.error });
});

// DIRECT NEON DB READS
app.get('/api/admin/email-automation/contacts', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT u.id, u.email, u.name, u.picture, u.created_at,
                   CASE
                     WHEN u.google_sub    IS NOT NULL THEN 'Google'
                     WHEN u.microsoft_sub IS NOT NULL THEN 'Microsoft'
                     ELSE '—'
                   END AS provider,
                   COALESCE(o.completed_count, 0) AS completed_orders,
                   COALESCE(o.pending_count,   0) AS pending_orders
            FROM users u
            LEFT JOIN (
                SELECT user_id,
                       COUNT(*) FILTER (WHERE status = 'Delivered') AS completed_count,
                       COUNT(*) FILTER (WHERE status = 'Pending')   AS pending_count
                FROM user_orders
                GROUP BY user_id
            ) o ON o.user_id = u.id
            ORDER BY u.created_at DESC
        `);
        res.json(result.rows);
    } catch (e) {
        console.error('contacts query failed:', e.message);
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/admin/email-automation/orders', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT o.id, o.product, o.price, o.status, o.occasion,
                   o.event_date, o.card_type, o.template,
                   o.order_date, o.delivery_date,
                   o.payment_status,
                   u.name  AS customer_name,
                   u.email AS email
            FROM user_orders o
            LEFT JOIN users u ON u.id = o.user_id
            ORDER BY o.id DESC
        `);
        res.json(result.rows);
    } catch (e) {
        console.error('orders query failed:', e.message);
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/admin/email-automation/payments', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT o.id,
                   o.price      AS amount,
                   'INR'        AS currency,
                   COALESCE(o.payment_status, 'Pending') AS status,
                   o.order_date AS created_at,
                   u.email      AS email,
                   u.name       AS customer_name
            FROM user_orders o
            LEFT JOIN users u ON u.id = o.user_id
            WHERE o.price IS NOT NULL
              AND o.price::text <> 'Pending Quote'
              AND o.price::text <> ''
            ORDER BY o.id DESC
        `);
        res.json(result.rows);
    } catch (e) {
        console.error('payments query failed:', e.message);
        res.status(500).json({ error: e.message });
    }
});

// Queue trigger. Two auth paths:
//   1. Dashboard "Run due queue now" → JWT cookie + X-Requested-With (CSRF).
//   2. External cron (cron-job.org / UptimeRobot) → X-API-Key matching
//      AUTOMATION_API_KEY. Each call wakes the Render free-tier instance and
//      drains any due jobs. This is the "wake only when needed" mechanism.
app.post('/api/admin/email-automation/run', authenticateTokenOrApiKey, async (req, res) => {
    try {
        if (cronRunning) {
            return res.json({ success: false, busy: true, message: 'Cron is already running; this trigger was skipped.' });
        }
        await processEmailQueue();
        const triggeredBy = (req.user && req.user.role === 'api-key') ? 'external-cron' : 'dashboard';
        res.json({ success: true, busy: false, message: 'Queue processed.', triggeredBy });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// SECURE SYNC (From Admin Panel using API Key)
app.post('/api/admin/email-automation/sync', apiLimiter, async (req, res) => {
    const crypto = require('crypto');
    const apiKey = req.headers['x-api-key'];
    if (!process.env.AUTOMATION_API_KEY) {
        return res.status(500).json({ error: 'AUTOMATION_API_KEY not configured on server.' });
    }
    const expectedSync = Buffer.from(String(process.env.AUTOMATION_API_KEY));
    const suppliedSync = Buffer.from(String(apiKey || ''));
    if (suppliedSync.length !== expectedSync.length || !crypto.timingSafeEqual(suppliedSync, expectedSync)) {
        return res.status(403).json({ error: 'Forbidden: Invalid API Key' });
    }

    const { contacts, orders } = req.body;
    try {
        await pool.query(
            `INSERT INTO settings (id, workflows, templates) VALUES (99, $1, $2)
             ON CONFLICT (id) DO UPDATE SET workflows = EXCLUDED.workflows, templates = EXCLUDED.templates`,
            [JSON.stringify(contacts || []), JSON.stringify(orders || [])]
        );
        res.json({ success: true, message: 'Data synced securely.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// BULK EMAIL SENDER (single, deduplicated route)
app.post('/api/admin/email-automation/send-bulk', authenticateToken, apiLimiter, async (req, res) => {
    const { recipients, subject, body } = req.body;
    if (!Array.isArray(recipients) || !recipients.length) return res.status(400).json({ error: 'No recipients' });
    if (!subject || !body) return res.status(400).json({ error: 'Subject and body are required' });
    if (recipients.length > 100) return res.status(400).json({ error: 'Maximum 100 recipients per batch. The dashboard automatically splits larger lists into batches of 100.' });

    const EMAIL_RE = /^[^\s,;<>]+@[^\s,;<>]+\.[^\s,;<>]+$/;
    const failedList = [];
    const suppressedList = [];

    // Route ALL batches through the queue → Stop actually cancels
    if (recipients.length > 0) {
        const batchId = require('crypto').randomUUID();
        let enqueued = 0;

        // Validate first so suppression can be batched in a single query.
        const validRecipients = [];
        for (const r of recipients) {
            if (!r || !EMAIL_RE.test(String(r.email || ''))) {
                failedList.push({ email: r?.email || '', error: 'Invalid email address' });
                continue;
            }
            validRecipients.push(r);
        }

        // Batch suppression check — one query instead of N.
        const suppressionSet = new Set();
        if (validRecipients.length) {
            try {
                const sup = await pool.query(
                    `SELECT LOWER(email) AS email FROM suppressions
                     WHERE LOWER(email) = ANY($1::text[])
                       AND scope IN ('all','marketing')`,
                    [validRecipients.map(r => String(r.email).toLowerCase())]
                );
                sup.rows.forEach(row => suppressionSet.add(row.email));
            } catch (_) { /* fail open like isSuppressed */ }
        }

        const unsubBase = process.env.UNSUBSCRIBE_URL || '';
        const siteCtx = baseContext();

        for (const r of validRecipients) {
            if (suppressionSet.has(String(r.email).toLowerCase())) {
                suppressedList.push({ email: r.email, reason: 'suppressed' });
                continue;
            }
            try {
                const orderCount = Math.max(0, Number(r.orderCount) || 0);
                const unsubUrl = unsubBase
                    + '?email=' + encodeURIComponent(String(r.email).trim())
                    + '&t=' + encodeURIComponent(unsubToken(r.email));
                const vars = {
                    ...siteCtx,
                    business_name: BUSINESS_NAME,
                    unsubscribe_url: unsubUrl,
                    name: r.name || 'there', customer_name: r.name || 'there',
                    first_name: (r.name || 'there').split(' ')[0], email: r.email || '',
                    ordersLeft: String(Math.max(0, 6 - orderCount)),
                    orderCount: String(orderCount),
                    orderId: r.orderId || ''
                };
                const pSubject = substituteText(subject, vars);
                const pText = substituteText(body, vars);
                const unsubFooterText = '\n\n---\nYou received this email because you interacted with ' + BUSINESS_NAME + '. Unsubscribe from marketing emails: ' + unsubUrl;
                const unsubFooterHtml = '<p style="margin-top:24px;padding-top:16px;border-top:1px solid #eeeef4;font-size:11px;line-height:1.6;color:#85879a">You received this email because you interacted with ' + BUSINESS_NAME + '. <a href="' + unsubUrl + '" style="color:#7047dc">Unsubscribe from marketing emails</a></p>';
                const pHtml = '<div style="font-family:Arial,sans-serif;font-size:14px;line-height:1.7;color:#222">'
                    + plainTextToHtml(pText) + unsubFooterHtml + '</div>';
                const pTextFinal = pText + unsubFooterText;
                const ins = await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at)
                     VALUES ($1, 'bulk', $2, $3, NOW())
                     ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [r.email, JSON.stringify({ _subject: pSubject, _html: pHtml, _text: pTextFinal }), 'bulk:' + batchId + ':' + r.email]
                );
                enqueued += ins.rowCount || 0;
            } catch (e) {
                failedList.push({ email: r.email, error: e.message });
            }
        }
        if (cronRunning) {
            console.log('Bulk enqueue: cron busy, jobs will drain on next tick.');
        } else {
            setImmediate(() => { processEmailQueue().catch(e => console.error('Bulk kick error:', e.message)); });
        }
        return res.status(202).json({
            success: true,
            queued: enqueued,
            sent: enqueued,
            failed: failedList.length,
            suppressed: suppressedList.length,
            sentList: [],
            failedList,
            suppressedList,
            batchId,
            message: 'Queued for async delivery'
        });
    }
});

// CANCEL BULK — removes queued rows for a batch
app.post('/api/admin/email-automation/cancel-bulk', authenticateToken, async (req, res) => {
    const { batchId } = req.body || {};
    if (!batchId) return res.status(400).json({ error: 'Missing batchId' });
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(batchId))) {
        return res.status(400).json({ error: 'batchId must be a UUID.' });
    }
    try {
        const r = await pool.query(
            `UPDATE email_queue
                SET status = 'skipped', last_error = 'user_cancelled'
              WHERE status = 'pending'
                AND template_id = 'bulk'
                AND related_id LIKE $1`,
            ['bulk:' + batchId + ':%']
        );
        res.json({ success: true, cancelled: r.rowCount || 0 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// QUEUE SNAPSHOT — read-only status counts + recent failures so the dashboard
// can show the operator exactly what is retryable before they click Retry.
app.get('/api/admin/email-automation/queue-stats', authenticateToken, async (req, res) => {
    try {
        const stats = await pool.query(
            `SELECT status, COUNT(*)::int AS cnt FROM email_queue GROUP BY status`
        );
        const counts = {};
        stats.rows.forEach(r => { counts[r.status] = r.cnt; });
        const recent = await pool.query(
            `SELECT id, recipient, template_id, status, last_error
               FROM email_queue
              WHERE status IN ('failed', 'skipped')
              ORDER BY id DESC
              LIMIT 15`
        );
        res.json({ counts, recent: recent.rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// RETRY FAILED — resets failed queue jobs to pending so the cron retries them.
// Body: { recipient?, template? } -> retry one specific failed job
// Body: {} -> retry ALL failed jobs
app.post('/api/admin/email-automation/retry-failed', authenticateToken, async (req, res) => {
    const { recipient, template, includeTimeouts } = req.body || {};
    // Timeout failures are ambiguous — the message may already have been
    // delivered. Skip them unless the caller explicitly opts in by passing
    // { includeTimeouts: true }. The dashboard surfaces a second confirmation
    // before setting that flag.
    const includeTimeoutsEnabled = includeTimeouts === true;
    const timeoutFilter = includeTimeoutsEnabled ? '' : "AND COALESCE(last_error, '') NOT ILIKE '%timeout%'";
    const attemptsReset = 'attempts = 0,';
    try {
        // Log rows record the human template name; the queue uses template_id.
        // Bulk logs say "Bulk Send" but the queue row is template_id='bulk'.
        const queueTemplate = template === 'Bulk Send' ? 'bulk' : template;
        let result;
        if (recipient && queueTemplate) {
            result = await pool.query(
                `UPDATE email_queue
                    SET status = 'pending', ${attemptsReset} last_error = NULL,
                        scheduled_at = NOW(), processing_started_at = NULL
                  WHERE id = (
                    SELECT id FROM email_queue
                    WHERE status = 'failed'
                      AND LOWER(recipient) = LOWER($1)
                      AND template_id = $2
                      ${timeoutFilter}
                    ORDER BY id DESC LIMIT 1
                  )
                  RETURNING id`,
                [recipient, queueTemplate]
            );
        } else if (recipient) {
            result = await pool.query(
                `UPDATE email_queue
                    SET status = 'pending', ${attemptsReset} last_error = NULL,
                        scheduled_at = NOW(), processing_started_at = NULL
                  WHERE status = 'failed'
                    AND LOWER(recipient) = LOWER($1)
                    ${timeoutFilter}
                  RETURNING id`,
                [recipient]
            );
        } else {
            result = await pool.query(
                `UPDATE email_queue
                    SET status = 'pending', ${attemptsReset} last_error = NULL,
                        scheduled_at = NOW(), processing_started_at = NULL
                  WHERE status = 'failed'
                  ${timeoutFilter}
                  RETURNING id`
            );
        }
        // Kick the queue so retries happen immediately, not at the next 60s cron tick.
        if (result.rowCount > 0 && !cronRunning) {
            setImmediate(() => { processEmailQueue().catch(e => console.error('Retry kick error:', e.message)); });
        }
        // Snapshot the queue so the dashboard can display real counts.
        let queueStats = {};
        try {
            const statsRes = await pool.query(
                `SELECT status, COUNT(*)::int AS cnt FROM email_queue GROUP BY status`
            );
            statsRes.rows.forEach(r => { queueStats[r.status] = r.cnt; });
        } catch (_) { /* diagnostics only — never fail the retry for this */ }
        res.json({ success: true, retried: result.rowCount || 0, queueStats });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// WEBHOOKS (From Main Website) — authenticated via X-API-Key
app.post('/api/webhooks/event', apiLimiter, async (req, res) => {
    if (!process.env.WEBHOOK_API_KEY) {
        return res.status(500).json({ error: 'WEBHOOK_API_KEY not configured on server.' });
    }
    const cryptoW = require('crypto');
    const expectedW = Buffer.from(String(process.env.WEBHOOK_API_KEY));
    const suppliedW = Buffer.from(String(req.headers['x-api-key'] || ''));
    if (suppliedW.length !== expectedW.length || !cryptoW.timingSafeEqual(suppliedW, expectedW)) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const {
        eventType, email, name, orderId, orderTotal, paymentStatus, paymentReference,
        receiptUrl, invitationUrl, eventDate, reviewUrl, userId, reviewId
    } = req.body;
    if (!eventType || !email) return res.status(400).json({ error: 'Missing eventType or email' });

    // Payload guards: no field can dominate an email body, and URL fields must
    // be http(s) so customers never receive javascript:/data: links.
    const LEN_CAPS = { name: 200, orderTotal: 64, paymentStatus: 64, paymentReference: 128, orderId: 128, userId: 64, reviewId: 64, eventDate: 64 };
    for (const [field, max] of Object.entries(LEN_CAPS)) {
        if (req.body[field] != null && String(req.body[field]).length > max) {
            return res.status(400).json({ error: 'Field too long: ' + field + ' (max ' + max + ')' });
        }
    }
    for (const field of ['receiptUrl', 'invitationUrl', 'reviewUrl']) {
        const v = req.body[field];
        if (v != null && v !== '' && !/^https?:\/\//i.test(String(v))) {
            return res.status(400).json({ error: 'Field must be an http(s) URL: ' + field });
        }
    }

    let templateId = null;
    let relatedId = null;

    if (eventType === 'user.signup') {
        if (!userId) return res.status(400).json({ error: 'Missing userId for user.signup' });
        templateId = 'welcome';
        relatedId = 'customer:' + userId;
    }
    if (eventType === 'review.submitted') {
        if (!reviewId) return res.status(400).json({ error: 'Missing reviewId for review.submitted' });
        templateId = 'review_thanks';
        relatedId = 'review:' + reviewId;
    }
    if (eventType === 'payment.succeeded') {
        if (!orderId) return res.status(400).json({ error: 'Missing orderId for payment.succeeded' });
        templateId = 'payment_success';
        relatedId = 'order:' + orderId;
    }
    if (eventType === 'order.delivered') {
        if (!orderId) return res.status(400).json({ error: 'Missing orderId for order.delivered' });
        templateId = 'delivery';
        relatedId = 'order:' + orderId;
    }
    if (eventType === 'payment.failed') {
        if (!orderId) return res.status(400).json({ error: 'Missing orderId for payment.failed' });
        templateId = 'payment_failed';
        relatedId = 'order-failed:' + orderId;
    }
    if (eventType === 'inquiry.created') {
        if (!orderId) return res.status(400).json({ error: 'Missing orderId (inquiry reference) for inquiry.created — required so each inquiry gets its own confirmation.' });
        templateId = 'inquiry_received';
        relatedId = 'inquiry:' + orderId;
    }
    if (eventType === 'support_issue.created') {
        if (!orderId) return res.status(400).json({ error: 'Missing orderId for support_issue.created' });
        if (!process.env.SUPPORT_TEAM_EMAIL) {
            return res.status(503).json({ error: 'SUPPORT_TEAM_EMAIL not configured on server.' });
        }
        templateId = 'support_alert';
        relatedId = 'support:' + orderId;
    }

    if (!templateId) return res.json({ success: true, message: 'No matching workflow' });

    const context = {
        customer_name: name || 'Customer',
        first_name: (name || 'Customer').split(' ')[0],
        order_id: orderId || '',
        order_total: orderTotal || '',
        payment_status: paymentStatus || (eventType === 'payment.succeeded' ? 'Paid' : '—'),
        payment_reference: paymentReference || 'N/A',
        receipt_url: receiptUrl || '',
        invitation_url: invitationUrl || '',
        event_date: eventDate || '',
        review_url: reviewUrl || '',
        site_url: process.env.SITE_URL || '',
        support_url: process.env.SUPPORT_URL || '',
        unsubscribe_url: process.env.UNSUBSCRIBE_URL || '',
        business_name: BUSINESS_NAME
    };

    try {
        const recipient = (eventType === 'support_issue.created')
            ? process.env.SUPPORT_TEAM_EMAIL
            : email;
        await pool.query(
            `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at)
             VALUES ($1, $2, $3, $4, NOW())
             ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
            [recipient, templateId, JSON.stringify(context), relatedId]
        );
        res.json({ success: true, message: 'Email queued!' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==========================================
// 5. AUTOMATION SCHEDULER (CRON JOB)
// ==========================================

const fs = require('fs');
const path = require('path');

// Load templates dynamically from the templates/ directory based on BUSINESS_TYPE
function loadFallbackTemplates() {
    const file = path.join(__dirname, 'templates', BUSINESS_TYPE + '.json');
    const fallback = path.join(__dirname, 'templates', 'general.json');
    try {
        const src = fs.existsSync(file) ? file : fallback;
        const raw = fs.readFileSync(src, 'utf8');
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed) && parsed.length) return parsed;
    } catch (e) {
        console.error('[templates] Could not load templates file for BUSINESS_TYPE=' + BUSINESS_TYPE + ': ' + e.message);
    }
    return [];
}
const FALLBACK_TEMPLATES_ARRAY = loadFallbackTemplates();
const ALL_TEMPLATE_IDS = ['welcome', 'signup_day1', 'signup_day3', 'signup_day5', 'inquiry_received', 'payment_success', 'payment_failed', 'loyalty_7th', 'delivery', 'event_7day', 'event_1day', 'review_request', 'review_reminder', 'support_alert', 'reengage', 'birthday', 'delivery_delay_internal', 'thank_you', 'order_received', 'review_thanks'];

async function loadTemplates() {
    try {
        const r = await pool.query(`SELECT templates FROM settings WHERE id != 99 ORDER BY id DESC LIMIT 1`);
        if (r.rows[0]?.templates) {
            const parsed = JSON.parse(r.rows[0].templates);
            if (Array.isArray(parsed) && parsed.length) return parsed;
        }
    } catch (_) { }
    return FALLBACK_TEMPLATES_ARRAY;
}

function baseContext() {
    return {
        site_url: process.env.SITE_URL || '',
        support_url: process.env.SUPPORT_URL || '',
        unsubscribe_url: process.env.UNSUBSCRIBE_URL || '',
        business_name: BUSINESS_NAME
    };
}

// Real deep-link builders — the poller fallback used to send customers to the
// homepage. Each pattern is overridable via env so you can match your routes.
function buildLinkUrl(envVar, defaultPattern, orderId) {
    const base = (process.env.SITE_URL || '').replace(/\/$/, '');
    const pattern = process.env[envVar] || defaultPattern;
    return base + pattern.replace('{id}', encodeURIComponent(String(orderId)));
}
function buildReceiptUrl(orderId) { return buildLinkUrl('RECEIPT_URL_PATTERN', '/orders/{id}', orderId); }
function buildInvitationUrl(orderId) { return buildLinkUrl('INVITATION_URL_PATTERN', '/invitation/{id}', orderId); }
function buildReviewUrl(orderId) { return buildLinkUrl('REVIEW_URL_PATTERN', '/orders/{id}/review', orderId); }

function formatEventDate(d) {
    if (!d) return '';
    const s = String(d);
    const m = s.match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (m) {
        const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
        return parseInt(m[3], 10) + ' ' + months[parseInt(m[2], 10) - 1] + ' ' + m[1];
    }
    const dt = d instanceof Date ? d : new Date(d);
    if (isNaN(dt.getTime())) return s;
    const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
    return dt.getUTCDate() + ' ' + months[dt.getUTCMonth()] + ' ' + dt.getUTCFullYear();
}

async function loadEnabledWorkflows() {
    try {
        const r = await pool.query(`SELECT workflows FROM settings WHERE id != 99 ORDER BY id DESC LIMIT 1`);
        if (r.rows[0]?.workflows) {
            const parsed = JSON.parse(r.rows[0].workflows);
            if (Array.isArray(parsed)) {
                const map = {};
                parsed.forEach(w => { map[w.id] = !!w.enabled; });
                return map;
            }
        }
    } catch (_) { }
    // Safe defaults mirror the dashboard: transactional ON, marketing OFF.
    return {
        signup_welcome: true,
        signup_nurture: false,
        inquiry_received: true,
        inquiry_sla: false,
        inquiry_followup: false,
        payment_success: true,
        payment_failed: true,
        delivery: true,
        event_reminders: true,
        review_thanks: true,
        order_received: true,
        delivery_delay_internal: true,
        review_request: false,
        support_route: true,
        repeat_reengage: false,
        milestone_dates: false,
        loyalty_7th: true,
        thank_you: true,
        bulk: true
    };
}

function templateWorkflowId(templateId) {
    const map = {
        welcome: 'signup_welcome',
        signup_day1: 'signup_nurture', signup_day3: 'signup_nurture', signup_day5: 'signup_nurture',
        inquiry_received: 'inquiry_received',
        payment_success: 'payment_success', payment_failed: 'payment_failed',
        delivery: 'delivery',
        event_7day: 'event_reminders', event_1day: 'event_reminders',
        review_thanks: 'review_thanks', thank_you: 'thank_you', order_received: 'order_received', review_request: 'review_request', review_reminder: 'review_request',
        reengage: 'repeat_reengage',
        birthday: 'milestone_dates',
        support_alert: 'support_route',
        loyalty_7th: 'loyalty_7th',
        delivery_delay_internal: 'delivery_delay_internal',
        bulk: 'bulk'
    };
    return map[templateId] || templateId;
}

function isTemplateAllowed(enabledMap, templateId) {
    if (templateId === 'bulk') return true;
    if (enabledMap === null) return true;
    const wfId = templateWorkflowId(templateId);
    return enabledMap[wfId] === true;
}

const TRANSACTIONAL_TEMPLATES = new Set([
    'welcome', 'payment_success', 'payment_failed', 'delivery',
    'thank_you', 'support_alert', 'loyalty_7th',
    'event_7day', 'event_1day',
    'inquiry_received', 'order_received', 'review_thanks', 'delivery_delay_internal'
]);

async function isSuppressed(email, templateId) {
    try {
        const isTx = TRANSACTIONAL_TEMPLATES.has(templateId);
        const scopeClause = isTx
            ? `AND scope = 'all'`
            : `AND scope IN ('all','marketing')`;
        const r = await pool.query(
            `SELECT 1 FROM suppressions WHERE LOWER(email) = LOWER($1) ${scopeClause} LIMIT 1`,
            [email]
        );
        return r.rowCount > 0;
    } catch (_) { return false; }
}

const MARKETING_TEMPLATES = new Set(['signup_day1', 'signup_day3', 'signup_day5', 'reengage', 'birthday', 'review_request', 'review_reminder']);

// Records a skipped queue job in the logs table so operators can see why a
// customer didn't receive an email (fixes the dashboard's always-zero
// "Suppressed / skipped" tile). Only called for user-visible skip reasons —
// workflow_disabled is deliberately silent to avoid a log storm on every
// cron tick while the admin has paused a workflow.
async function logSkipped(job, detail) {
    try {
        await pool.query(
            `INSERT INTO logs (recipient, template, status, detail) VALUES ($1, $2, 'skipped', $3)`,
            [job.recipient, job.template_id, detail]
        );
    } catch (_) { /* never let logging failure break the queue */ }
}

let cronRunning = false;
async function processEmailQueue() {
    if (cronRunning) { console.log('Cron: previous run still active, skipping.'); return; }
    cronRunning = true;
    try {
        const enabledMap = await loadEnabledWorkflows();

        // Recover jobs stuck in 'processing' for > 10 minutes
        await pool.query(`UPDATE email_queue SET status = 'pending', processing_started_at = NULL
            WHERE status = 'processing' AND processing_started_at IS NOT NULL
              AND processing_started_at < NOW() - INTERVAL '10 minutes'`);

        // Retry failed jobs (up to 3 attempts) after 5 minutes
        await pool.query(`UPDATE email_queue SET status = 'pending', scheduled_at = NOW(), processing_started_at = NULL
            WHERE status = 'failed' AND attempts < 3
              AND COALESCE(processing_started_at, scheduled_at) < NOW() - INTERVAL '5 minutes'`);

        // ============ 1. WELCOME — find NEW users not yet queued ============
        if (isTemplateAllowed(enabledMap, 'welcome')) try {
            const newUsers = await pool.query(`
                SELECT u.id, u.email, COALESCE(u.name, 'Customer') AS name
                FROM users u
                WHERE u.email IS NOT NULL
                  AND u.created_at > NOW() - INTERVAL '7 days'
                  AND NOT EXISTS (
                    SELECT 1 FROM email_queue q
                    WHERE q.template_id = 'welcome' AND q.related_id = 'customer:' || u.id
                  )
                ORDER BY u.id ASC LIMIT 100
            `);
            for (const u of newUsers.rows) {
                if (await isSuppressed(u.email, 'welcome')) continue;
                await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at)
                     VALUES ($1, 'welcome', $2, $3, NOW())
                     ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [u.email, JSON.stringify({ ...baseContext(), customer_name: u.name, first_name: String(u.name).split(' ')[0] }), 'customer:' + u.id]
                );
            }
        } catch (e) { console.error('Welcome poll error:', e.message); }

        // ============ 2. PAYMENT SUCCESS — only verified paid orders not yet queued ============
        if (isTemplateAllowed(enabledMap, 'payment_success')) try {
            const paid = await pool.query(`
                SELECT o.id, o.price, o.payment_status, u.email, u.name,
                       COALESCE(o.payment_reference, o.transaction_id) AS payment_ref
                FROM user_orders o
                JOIN users u ON u.id = o.user_id
                WHERE o.price IS NOT NULL AND o.price::text <> 'Pending Quote' AND o.price::text <> ''
                  AND LOWER(COALESCE(o.payment_status, '')) IN ('paid','confirmed','success','succeeded','completed')
                  AND COALESCE(o.paid_at, o.order_date) > NOW() - INTERVAL '14 days'
                  AND u.email IS NOT NULL
                  AND NOT EXISTS (
                    SELECT 1 FROM email_queue q
                    WHERE q.template_id = 'payment_success' AND q.related_id = 'order:' || o.id
                  )
                ORDER BY o.id ASC LIMIT 100
            `);
            for (const o of paid.rows) {
                if (await isSuppressed(o.email, 'payment_success')) continue;
                await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at)
                     VALUES ($1, 'payment_success', $2, $3, NOW())
                     ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [o.email, JSON.stringify({ ...baseContext(), customer_name: o.name || 'Customer', first_name: String(o.name || 'Customer').split(' ')[0], order_id: o.id, order_total: o.price || '', payment_status: (['paid', 'confirmed', 'success', 'succeeded', 'completed'].includes(String(o.payment_status || '').toLowerCase()) ? 'Confirmed' : (o.payment_status || 'Confirmed')), payment_reference: o.payment_ref || ('ORD-' + o.id), receipt_url: buildReceiptUrl(o.id) }), 'order:' + o.id]
                );
            }
        } catch (e) { console.error('Payment poll error:', e.message); }

        // ============ 3b. ORDER RECEIVED + THANK YOU ============
        if (isTemplateAllowed(enabledMap, 'order_received')) try {
            const newOrders = await pool.query(`
                SELECT o.id, o.price, o.status, o.delivery_date, u.email, u.name
                FROM user_orders o
                JOIN users u ON u.id = o.user_id
                WHERE u.email IS NOT NULL
                  AND o.order_date IS NOT NULL
                  AND o.order_date > NOW() - INTERVAL '3 days'
                  AND NOT EXISTS (
                    SELECT 1 FROM email_queue q
                    WHERE q.template_id = 'order_received' AND q.related_id = 'order-received:' || o.id
                  )
                ORDER BY o.id ASC LIMIT 100
            `);
            for (const o of newOrders.rows) {
                if (await isSuppressed(o.email, 'order_received')) continue;
                await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at)
                     VALUES ($1, 'order_received', $2, $3, NOW())
                     ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [o.email, JSON.stringify({ ...baseContext(), customer_name: o.name || 'Customer', first_name: String(o.name || 'Customer').split(' ')[0], order_id: o.id, order_total: o.price || '', receipt_url: buildReceiptUrl(o.id) }), 'order-received:' + o.id]
                );
            }
        } catch (e) { if (!/does not exist/i.test(e.message)) console.error('Order received poll error:', e.message); }

        if (isTemplateAllowed(enabledMap, 'thank_you')) try {
            const completedOrders = await pool.query(`
                SELECT o.id, o.event_date, u.email, u.name
                FROM user_orders o
                JOIN users u ON u.id = o.user_id
                WHERE u.email IS NOT NULL
                  AND LOWER(COALESCE(o.status, '')) IN ('delivered','completed')
                  AND o.delivery_date IS NOT NULL
                  AND o.delivery_date BETWEEN NOW() - INTERVAL '14 days' AND NOW() - INTERVAL '7 days'
                  AND NOT EXISTS (
                    SELECT 1 FROM email_queue q
                    WHERE q.template_id = 'thank_you' AND q.related_id = 'order-thanks:' || o.id
                  )
                ORDER BY o.id ASC LIMIT 100
            `);
            for (const o of completedOrders.rows) {
                if (await isSuppressed(o.email, 'thank_you')) continue;
                await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at)
                     VALUES ($1, 'thank_you', $2, $3, NOW())
                     ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [o.email, JSON.stringify({ ...baseContext(), customer_name: o.name || 'Customer', first_name: String(o.name || 'Customer').split(' ')[0], order_id: o.id, invitation_url: buildInvitationUrl(o.id), event_date: formatEventDate(o.event_date) }), 'order-thanks:' + o.id]
                );
            }
        } catch (e) { if (!/does not exist/i.test(e.message)) console.error('Thank you poll error:', e.message); }

        // ============ 3c. DELIVERY DELAY — internal alert ============
        if (isTemplateAllowed(enabledMap, 'delivery_delay_internal') && process.env.SUPPORT_TEAM_EMAIL) try {
            const delays = await pool.query(`
                SELECT o.id, o.delivery_date, u.name
                FROM user_orders o
                JOIN users u ON u.id = o.user_id
                WHERE LOWER(COALESCE(o.status, '')) NOT IN ('delivered','completed','cancelled','refunded')
                  AND o.delivery_date IS NOT NULL
                  AND o.delivery_date < NOW() - INTERVAL '1 day'
                  AND NOT EXISTS (
                    SELECT 1 FROM email_queue q
                    WHERE q.template_id = 'delivery_delay_internal' AND q.related_id = 'delay:' || o.id
                  )
                ORDER BY o.id ASC LIMIT 20
            `);
            for (const o of delays.rows) {
                await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at)
                     VALUES ($1, 'delivery_delay_internal', $2, $3, NOW())
                     ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [process.env.SUPPORT_TEAM_EMAIL, JSON.stringify({ ...baseContext(), customer_name: o.name || 'Customer', order_id: o.id, receipt_url: buildReceiptUrl(o.id) }), 'delay:' + o.id]
                );
            }
        } catch (e) { if (!/does not exist/i.test(e.message)) console.error('Delay alert poll error:', e.message); }

        // ============ 4. REVIEW SUBMITTED ============
        if (isTemplateAllowed(enabledMap, 'review_thanks')) try {
            const reviews = await pool.query(`
                SELECT r.id, r.rating, u.email, u.name
                FROM reviews r
                JOIN users u ON u.id = r.user_id
                WHERE u.email IS NOT NULL
                  AND r.created_at > NOW() - INTERVAL '1 day'
                  AND NOT EXISTS (
                    SELECT 1 FROM email_queue q
                    WHERE q.template_id = 'review_thanks' AND q.related_id = 'review:' || r.id
                  )
                ORDER BY r.id ASC LIMIT 100
            `);
            for (const r of reviews.rows) {
                if (await isSuppressed(r.email, 'review_thanks')) continue;
                await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at)
                     VALUES ($1, 'review_thanks', $2, $3, NOW())
                     ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [r.email, JSON.stringify({ ...baseContext(), customer_name: r.name || 'Customer', first_name: String(r.name || 'Customer').split(' ')[0] }), 'review:' + r.id]
                );
            }
        } catch (e) {
            if (!/does not exist/.test(e.message)) console.error('Review poll error:', e.message);
        }

        // ============ 4b. SIGNUP NURTURE (Day 1 / 3 / 5) ============
        if (isTemplateAllowed(enabledMap, 'signup_day1')) try {
            const nurture = await pool.query(`
                SELECT u.id, u.email, COALESCE(u.name, 'Customer') AS name
                FROM users u
                WHERE u.email IS NOT NULL
                  AND u.created_at BETWEEN NOW() - INTERVAL '2 days' AND NOW() - INTERVAL '1 day'
                  AND COALESCE(u.marketing_consent, true) = true
                  AND NOT EXISTS (SELECT 1 FROM user_orders o WHERE o.user_id = u.id)
                  AND NOT EXISTS (SELECT 1 FROM email_queue q WHERE q.template_id = 'signup_day5' AND q.related_id = 'customer:' || u.id)
                ORDER BY u.created_at ASC
                LIMIT 50
            `);
            for (const u of nurture.rows) {
                if (await isSuppressed(u.email, 'signup_day1')) continue;
                const ctx = JSON.stringify({ ...baseContext(), customer_name: u.name, first_name: String(u.name).split(' ')[0] });
                await pool.query(`INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at) VALUES ($1,'signup_day1',$2,$3,GREATEST(NOW(), $4::timestamp + INTERVAL '1 day')) ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`, [u.email, ctx, 'customer:' + u.id, u.created_at]);
                await pool.query(`INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at) VALUES ($1,'signup_day3',$2,$3,GREATEST(NOW(), $4::timestamp + INTERVAL '3 days')) ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`, [u.email, ctx, 'customer:' + u.id, u.created_at]);
                await pool.query(`INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at) VALUES ($1,'signup_day5',$2,$3,GREATEST(NOW(), $4::timestamp + INTERVAL '5 days')) ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`, [u.email, ctx, 'customer:' + u.id, u.created_at]);
            }
        } catch (e) { if (!/does not exist/i.test(e.message)) console.error('Nurture poll error:', e.message); }

        // ============ 4c. PAYMENT FAILED ============
        if (isTemplateAllowed(enabledMap, 'payment_failed')) try {
            const failedPay = await pool.query(`
                SELECT o.id, o.price, u.email, u.name,
                       COALESCE(o.payment_reference, o.transaction_id) AS payment_ref
                FROM user_orders o
                JOIN users u ON u.id = o.user_id
                WHERE LOWER(COALESCE(o.payment_status, '')) IN ('failed','failure','declined','rejected')
                  AND COALESCE(o.order_date, NOW()) > NOW() - INTERVAL '14 days'
                  AND u.email IS NOT NULL
                  AND NOT EXISTS (SELECT 1 FROM email_queue q WHERE q.template_id = 'payment_failed' AND q.related_id = 'order-failed:' || o.id)
                ORDER BY o.id ASC LIMIT 50
            `);
            for (const o of failedPay.rows) {
                if (await isSuppressed(o.email, 'payment_failed')) continue;
                await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at) VALUES ($1,'payment_failed',$2,$3,NOW()) ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [o.email, JSON.stringify({ ...baseContext(), customer_name: o.name || 'Customer', order_id: o.id, order_total: o.price || '', payment_reference: o.payment_ref || 'N/A', receipt_url: buildReceiptUrl(o.id) }), 'order-failed:' + o.id]
                );
            }
        } catch (e) { if (!/does not exist/i.test(e.message)) console.error('Payment failed poll error:', e.message); }

        // ============ 4c2. SUPPORT ISSUES — internal alert ============
        if (isTemplateAllowed(enabledMap, 'support_route') && process.env.SUPPORT_TEAM_EMAIL) try {
            const issues = await pool.query(`
                SELECT o.id, u.name
                FROM user_orders o
                JOIN users u ON u.id = o.user_id
                WHERE LOWER(COALESCE(o.status, '')) = 'issue'
                  AND NOT EXISTS (
                    SELECT 1 FROM email_queue q
                    WHERE q.template_id = 'support_alert' AND q.related_id = 'support:' || o.id
                  )
                LIMIT 20
            `);
            for (const o of issues.rows) {
                await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at)
                     VALUES ($1, 'support_alert', $2, $3, NOW())
                     ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [process.env.SUPPORT_TEAM_EMAIL, JSON.stringify({ ...baseContext(), customer_name: o.name || 'Customer', order_id: o.id, receipt_url: buildReceiptUrl(o.id) }), 'support:' + o.id]
                );
            }
        } catch (e) { if (!/does not exist/i.test(e.message)) console.error('Support alert poll error:', e.message); }

        // ============ 4d. REVIEW REQUEST (2 days after delivery) ============
        if (isTemplateAllowed(enabledMap, 'review_request')) try {
            const toReview = await pool.query(`
                SELECT o.id, o.delivery_date, o.event_date, u.email, u.name
                FROM user_orders o
                JOIN users u ON u.id = o.user_id
                WHERE LOWER(COALESCE(o.status, '')) = 'delivered' AND o.delivery_date IS NOT NULL
                  AND o.delivery_date BETWEEN NOW() - INTERVAL '9 days' AND NOW() - INTERVAL '2 days'
                  AND u.email IS NOT NULL
                  AND NOT EXISTS (SELECT 1 FROM email_queue q WHERE q.template_id = 'review_request' AND q.related_id = 'order-review-req:' || o.id)
                ORDER BY o.id ASC LIMIT 50
            `);
            for (const o of toReview.rows) {
                if (await isSuppressed(o.email, 'review_request')) continue;
                const ctx = JSON.stringify({ ...baseContext(), customer_name: o.name || 'Customer', order_id: o.id, review_url: buildReviewUrl(o.id), invitation_url: buildInvitationUrl(o.id), event_date: formatEventDate(o.event_date) });
                const client = await pool.connect();
                try {
                    await client.query('BEGIN');
                    await client.query(`INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at) VALUES ($1,'review_request',$2,$3,NOW()) ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`, [o.email, ctx, 'order-review-req:' + o.id]);
                    await client.query(`INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at) VALUES ($1,'review_reminder',$2,$3, GREATEST(NOW(), $4::timestamp + INTERVAL '7 days')) ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`, [o.email, ctx, 'order-review-req:' + o.id, o.delivery_date]);
                    await client.query('COMMIT');
                } catch (txErr) {
                    await client.query('ROLLBACK').catch(() => { });
                    // Leave both rows uninserted so the next cron cycle re-selects this order.
                    console.error('Review request pair insert failed for order ' + o.id + ':', txErr.message);
                } finally {
                    client.release();
                }
            }
        } catch (e) { if (!/does not exist/i.test(e.message)) console.error('Review request poll error:', e.message); }

        // ============ 4e. EVENT REMINDERS (7d / 1d) ============
        if (isTemplateAllowed(enabledMap, 'event_7day')) try {
            const r7 = await pool.query(`
                SELECT o.id, o.event_date, u.email, u.name
                FROM user_orders o JOIN users u ON u.id = o.user_id
                WHERE o.event_date IS NOT NULL
                  AND o.event_date::text <> ''
                  AND (
                    CASE
                      WHEN o.event_date::text ~ '^\\d{4}-\\d{2}-\\d{2}' THEN o.event_date::text::date
                      WHEN o.event_date::text ~ '^\\d{1,2}\\s+[A-Za-z]+\\s+\\d{4}$' THEN to_date(o.event_date::text, 'DD Month YYYY')
                      ELSE NULL
                    END
                  ) BETWEEN (NOW() + INTERVAL '6 days')::date AND (NOW() + INTERVAL '7 days')::date
                  AND COALESCE(o.status, '') NOT IN ('Cancelled','Refunded')
                  AND u.email IS NOT NULL
                  AND NOT EXISTS (SELECT 1 FROM email_queue q WHERE q.template_id = 'event_7day' AND q.related_id = 'order-evt7:' || o.id)
                LIMIT 50
            `);
            for (const o of r7.rows) {
                if (await isSuppressed(o.email, 'event_7day')) continue;
                await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at) VALUES ($1,'event_7day',$2,$3,NOW()) ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [o.email, JSON.stringify({ ...baseContext(), customer_name: o.name || 'Customer', order_id: o.id, event_date: formatEventDate(o.event_date), invitation_url: buildInvitationUrl(o.id) }), 'order-evt7:' + o.id]
                );
            }
            const r1 = await pool.query(`
                SELECT o.id, o.event_date, u.email, u.name
                FROM user_orders o JOIN users u ON u.id = o.user_id
                WHERE o.event_date IS NOT NULL
                  AND o.event_date::text <> ''
                  AND (
                    CASE
                      WHEN o.event_date::text ~ '^\\d{4}-\\d{2}-\\d{2}' THEN o.event_date::text::date
                      WHEN o.event_date::text ~ '^\\d{1,2}\\s+[A-Za-z]+\\s+\\d{4}$' THEN to_date(o.event_date::text, 'DD Month YYYY')
                      ELSE NULL
                    END
                  ) = (NOW() + INTERVAL '1 day')::date
                  AND COALESCE(o.status, '') NOT IN ('Cancelled','Refunded')
                  AND u.email IS NOT NULL
                  AND NOT EXISTS (SELECT 1 FROM email_queue q WHERE q.template_id = 'event_1day' AND q.related_id = 'order-evt1:' || o.id)
                LIMIT 50
            `);
            for (const o of r1.rows) {
                if (await isSuppressed(o.email, 'event_1day')) continue;
                await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at) VALUES ($1,'event_1day',$2,$3,NOW()) ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [o.email, JSON.stringify({ ...baseContext(), customer_name: o.name || 'Customer', order_id: o.id, event_date: formatEventDate(o.event_date), invitation_url: buildInvitationUrl(o.id) }), 'order-evt1:' + o.id]
                );
            }
        } catch (e) { if (!/does not exist/i.test(e.message)) console.error('Event reminder poll error:', e.message); }

        // ============ 4f. LOYALTY 7th — 6 completed paid orders ============
        if (isTemplateAllowed(enabledMap, 'loyalty_7th')) try {
            const loyalty = await pool.query(`
                SELECT u.id, u.email, COALESCE(u.name, 'Customer') AS name, u.created_at, COUNT(o.id) AS completed_count
                FROM users u
                JOIN user_orders o ON o.user_id = u.id
                WHERE u.email IS NOT NULL
                  AND LOWER(COALESCE(o.status, '')) = 'delivered'
                  AND LOWER(COALESCE(o.payment_status, '')) IN ('paid','confirmed','success','succeeded','completed')
                GROUP BY u.id, u.email, u.name
                HAVING COUNT(o.id) >= 6
                   AND NOT EXISTS (SELECT 1 FROM email_queue q WHERE q.template_id = 'loyalty_7th' AND q.related_id = 'loyalty:' || u.id)
                LIMIT 50
            `).catch(() => ({ rows: [] }));
            for (const u of loyalty.rows) {
                if (await isSuppressed(u.email, 'loyalty_7th')) continue;
                await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at) VALUES ($1,'loyalty_7th',$2,$3,NOW()) ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [u.email, JSON.stringify({ ...baseContext(), customer_name: u.name, first_name: String(u.name).split(' ')[0] }), 'loyalty:' + u.id]
                );
            }
        } catch (e) { if (!/does not exist/i.test(e.message)) console.error('Loyalty poll error:', e.message); }

        // ============ 4g. RE-ENGAGE — no order in 60 days ============
        if (isTemplateAllowed(enabledMap, 'reengage')) try {
            const reengage = await pool.query(`
                SELECT u.id, u.email, COALESCE(u.name, 'Customer') AS name
                FROM users u
                WHERE u.email IS NOT NULL
                  AND COALESCE(u.marketing_consent, true) = true
                  AND NOT EXISTS (SELECT 1 FROM user_orders o WHERE o.user_id = u.id AND o.order_date > NOW() - INTERVAL '60 days')
                  AND EXISTS (SELECT 1 FROM user_orders o WHERE o.user_id = u.id AND o.order_date < NOW() - INTERVAL '60 days')
                  AND NOT EXISTS (SELECT 1 FROM email_queue q WHERE q.template_id = 'reengage' AND q.related_id = 'reengage:' || u.id || ':' || FLOOR(EXTRACT(EPOCH FROM NOW()) / (90*86400)))
                ORDER BY u.id ASC LIMIT 50
            `).catch(() => ({ rows: [] }));
            for (const u of reengage.rows) {
                if (await isSuppressed(u.email, 'reengage')) continue;
                await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at) VALUES ($1,'reengage',$2,$3,NOW()) ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [u.email, JSON.stringify({ ...baseContext(), customer_name: u.name, first_name: String(u.name).split(' ')[0] }), 'reengage:' + u.id + ':' + Math.floor(Date.now() / (90 * 86400000))]
                );
            }
        } catch (e) { if (!/does not exist/i.test(e.message)) console.error('Reengage poll error:', e.message); }

        // ============ 4h. BIRTHDAY — today's birthdays ============
        if (isTemplateAllowed(enabledMap, 'birthday')) try {
            const bdays = await pool.query(`
                SELECT u.id, u.email, COALESCE(u.name, 'Customer') AS name
                FROM users u
                WHERE u.email IS NOT NULL
                  AND u.birthday IS NOT NULL
                  AND EXTRACT(MONTH FROM u.birthday) = EXTRACT(MONTH FROM CURRENT_DATE)
                  AND EXTRACT(DAY FROM u.birthday) = EXTRACT(DAY FROM CURRENT_DATE)
                  AND COALESCE(u.marketing_consent, true) = true
                  AND NOT EXISTS (SELECT 1 FROM email_queue q WHERE q.template_id = 'birthday' AND q.related_id = 'birthday:' || u.id || ':' || EXTRACT(YEAR FROM CURRENT_DATE))
                LIMIT 50
            `).catch(() => ({ rows: [] }));
            for (const u of bdays.rows) {
                if (await isSuppressed(u.email, 'birthday')) continue;
                await pool.query(
                    `INSERT INTO email_queue (recipient, template_id, context, related_id, scheduled_at) VALUES ($1,'birthday',$2,$3,NOW()) ON CONFLICT (template_id, related_id) WHERE related_id IS NOT NULL DO NOTHING`,
                    [u.email, JSON.stringify({ ...baseContext(), customer_name: u.name, first_name: String(u.name).split(' ')[0] }), 'birthday:' + u.id + ':' + new Date().getFullYear()]
                );
            }
        } catch (e) { if (!/does not exist|column.*does not exist/i.test(e.message)) console.error('Birthday poll error:', e.message); }

        // ============ 5. PROCESS QUEUE (atomic claim) ============
        const templates = await loadTemplates();
        const jobs = await pool.query(`
            UPDATE email_queue SET status = 'processing', processing_started_at = NOW()
            WHERE id IN (
                SELECT id FROM email_queue
                WHERE status = 'pending' AND scheduled_at <= NOW()
                ORDER BY scheduled_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING *
        `);

        for (const job of jobs.rows) {
            if (job.template_id === 'bulk') {
                if (await isSuppressed(job.recipient, 'bulk')) {
                    await pool.query(`UPDATE email_queue SET status = 'skipped', last_error = 'suppressed' WHERE id = $1`, [job.id]);
                    await logSkipped(job, 'suppressed');
                    continue;
                }
                try {
                    const consent = await pool.query(
                        `SELECT marketing_consent FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1`,
                        [job.recipient]
                    );
                    if (consent.rowCount && consent.rows[0].marketing_consent === false) {
                        await pool.query(`UPDATE email_queue SET status = 'skipped', last_error = 'consent_withdrawn' WHERE id = $1`, [job.id]);
                        await logSkipped(job, 'consent_withdrawn');
                        continue;
                    }
                } catch (_) { /* allow send */ }
                const ctx = job.context || {};
                const result = await sendEmail(job.recipient, ctx._subject || '(no subject)', ctx._html || '', 'Bulk Send', ctx._text || '', true);
                if (result.success) await pool.query(`UPDATE email_queue SET status = 'sent' WHERE id = $1`, [job.id]);
                else if (result.error && /timeout/i.test(result.error)) await pool.query(`UPDATE email_queue SET status = 'failed', attempts = 3, last_error = $1 WHERE id = $2`, [result.error, job.id]);
                else await pool.query(`UPDATE email_queue SET status = 'failed', attempts = attempts + 1, last_error = $1 WHERE id = $2`, [result.error, job.id]);
                await new Promise(r => setTimeout(r, 2000));
                continue;
            }
            if (!isTemplateAllowed(enabledMap, job.template_id)) {
                await pool.query(`UPDATE email_queue SET status = 'skipped', last_error = 'workflow_disabled' WHERE id = $1`, [job.id]);
                continue;
            }
            if (await isSuppressed(job.recipient, job.template_id)) {
                await pool.query(`UPDATE email_queue SET status = 'skipped', last_error = 'suppressed' WHERE id = $1`, [job.id]);
                await logSkipped(job, 'suppressed');
                continue;
            }
            if (['review_request', 'review_reminder'].includes(job.template_id)) {
                try {
                    const reviewed = await pool.query(
                        `SELECT 1 FROM reviews r JOIN users u ON u.id = r.user_id
                          WHERE LOWER(u.email) = LOWER($1) LIMIT 1`,
                        [job.recipient]
                    );
                    if (reviewed.rowCount > 0) {
                        await pool.query(`UPDATE email_queue SET status = 'skipped', last_error = 'already_reviewed' WHERE id = $1`, [job.id]);
                        await logSkipped(job, 'already_reviewed');
                        continue;
                    }
                } catch (_) { /* allow send if reviews table missing */ }
            }
            if (['signup_day3', 'signup_day5'].includes(job.template_id)) {
                try {
                    const ordered = await pool.query(
                        `SELECT 1 FROM user_orders o
                           JOIN users u ON u.id = o.user_id
                          WHERE LOWER(u.email) = LOWER($1) LIMIT 1`,
                        [job.recipient]
                    );
                    if (ordered.rowCount > 0) {
                        await pool.query(`UPDATE email_queue SET status = 'skipped', last_error = 'user_ordered' WHERE id = $1`, [job.id]);
                        continue;
                    }
                } catch (_) { /* allow send if join fails */ }
            }
            if (MARKETING_TEMPLATES.has(job.template_id)) {
                try {
                    const consent = await pool.query(
                        `SELECT marketing_consent FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1`,
                        [job.recipient]
                    );
                    if (consent.rowCount && consent.rows[0].marketing_consent === false) {
                        await pool.query(`UPDATE email_queue SET status = 'skipped', last_error = 'consent_withdrawn' WHERE id = $1`, [job.id]);
                        await logSkipped(job, 'consent_withdrawn');
                        continue;
                    }
                } catch (_) { /* allow send */ }
            }
            if (job.template_id === 'payment_failed') {
                try {
                    const m = (job.related_id || '').match(/^order-failed:(.+)$/);
                    if (m) {
                        const st = await pool.query(`SELECT payment_status FROM user_orders WHERE id = $1 LIMIT 1`, [m[1]]);
                        const ps = String((st.rows[0] || {}).payment_status || '').toLowerCase();
                        if (['paid', 'confirmed', 'success', 'succeeded', 'completed'].includes(ps)) {
                            await pool.query(`UPDATE email_queue SET status = 'skipped', last_error = 'payment_now_succeeded' WHERE id = $1`, [job.id]);
                            await logSkipped(job, 'payment_now_succeeded');
                            continue;
                        }
                    }
                } catch (_) { /* allow send */ }
            }
            const template = templates.find(t => t.id === job.template_id);
            if (!template) {
                console.warn('template_not_found:', job.template_id, 'for', job.recipient);
                await pool.query(`UPDATE email_queue SET status = 'skipped', last_error = 'template_not_found' WHERE id = $1`, [job.id]);
                continue;
            }
            const vars = job.context || {};
            const subject = substituteText(template.subject, vars);
            const html = substituteHtml(template.html, vars);
            const text = substituteText(template.text || '', vars);
            const isMarketing = MARKETING_TEMPLATES.has(job.template_id) || job.template_id === 'bulk';
            const result = await sendEmail(job.recipient, subject, html, job.template_id, text, isMarketing);
            if (result.success) {
                await pool.query(`UPDATE email_queue SET status = 'sent' WHERE id = $1`, [job.id]);
            } else if (result.error && /timeout/i.test(result.error)) {
                await pool.query(
                    `UPDATE email_queue SET status = 'failed', attempts = 3, last_error = $1 WHERE id = $2`,
                    [result.error, job.id]
                );
            } else {
                await pool.query(
                    `UPDATE email_queue SET status = 'failed', attempts = attempts + 1, last_error = $1 WHERE id = $2`,
                    [result.error, job.id]
                );
            }
            // Pace sends: ~2s between each → ~30/min, safely under Gmail quota
            await new Promise(r => setTimeout(r, 2000));
        }
    } catch (e) {
        console.error("Cron error:", e);
    } finally {
        cronRunning = false;
    }
}

cron.schedule('*/30 * * * * *', processEmailQueue);

// ==========================================
// START SERVER
// ==========================================
// Global Error Handler (must be placed after all routes)
app.use((err, req, res, next) => {
    if (err && /CORS policy/i.test(err.message || '')) {
        return res.status(403).json({ error: 'Origin not allowed by CORS policy.', origin: req.headers.origin || null });
    }
    console.error(err.stack);
    res.status(500).json({ error: err.message || 'Internal Server Error' });
});

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log(`Backend running on port ${PORT}`);
    console.log(`[system] Developed by AmaraChintha Akhil`);
});

const shutdown = (signal) => {
    console.log(`${signal} received — closing HTTP server and DB pool.`);
    server.close(() => {
        pool.end(() => process.exit(0));
    });
    // Give in-flight requests 5 s to finish, then force-exit.
    setTimeout(() => process.exit(1), 5000).unref();
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));