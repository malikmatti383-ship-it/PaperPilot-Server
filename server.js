/**
 * PaperPilot backend — Google (Gmail) login + per-user cloud data sync.
 *
 * Endpoints:
 *   GET  /healthz               -> { ok: true }
 *   GET  /auth/google           -> redirect to Google consent
 *   GET  /auth/google/callback  -> code exchange, session creation, redirect to PWA with #token=
 *   GET  /api/me                (auth) -> { email, name, picture, plan }
 *   GET  /api/data              (auth) -> { data, updatedAt }
 *   POST /api/data              (auth) -> upsert { data }, returns { updatedAt }
 *   POST /api/logout            (auth) -> delete session
 *
 * Security notes:
 * - Session tokens are 32 random bytes (hex). Only the SHA-256 hash is stored.
 * - Tokens/secrets are NEVER logged.
 * - Sessions expire after 365 days (persistent login; logout only on explicit /api/logout).
 */
'use strict';

require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const jazzcash = require('./jazzcash');

// ---------------------------------------------------------------- env
const PORT = parseInt(process.env.PORT || '3000', 10);
const MONGODB_URI = (process.env.MONGODB_URI || '').trim();
const GOOGLE_CLIENT_ID = (process.env.GOOGLE_CLIENT_ID || '').trim();
const GOOGLE_CLIENT_SECRET = (process.env.GOOGLE_CLIENT_SECRET || '').trim();
const SERVER_URL = (process.env.SERVER_URL || '').trim().replace(/\/$/, '');
const PWA_URL = (process.env.PWA_URL || 'https://malikmatti383-ship-it.github.io/Paper-Stock/').replace(/\/$/, '');

// JazzCash (optional — payments disabled until these are set)
const JC = {
  merchantId: process.env.JAZZCASH_MERCHANT_ID || '',
  password: process.env.JAZZCASH_PASSWORD || '',
  integritySalt: process.env.JAZZCASH_INTEGRITY_SALT || '',
  sandbox: (process.env.JAZZCASH_SANDBOX || 'true') !== 'false',
};
const JC_POST_URL = JC.sandbox ? jazzcash.SANDBOX_POST_URL : jazzcash.PROD_POST_URL;
const JC_CONFIGURED = Boolean(JC.merchantId && JC.password && JC.integritySalt && SERVER_URL);
if (!JC_CONFIGURED) console.warn('[config] JazzCash not configured — /api/pay/* will return 503.');

const SESSION_DAYS = 365;

function required(name, val) {
  if (!val) {
    console.error(`[config] Missing required env var: ${name}`);
    process.exit(1);
  }
}
required('MONGODB_URI', MONGODB_URI);
required('GOOGLE_CLIENT_ID', GOOGLE_CLIENT_ID);
required('GOOGLE_CLIENT_SECRET', GOOGLE_CLIENT_SECRET);
if (!SERVER_URL) console.warn('[config] SERVER_URL not set — OAuth redirect_uri will be wrong. Set it to your Render URL.');

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo';

// ---------------------------------------------------------------- helpers
function sha256hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

/** Pure function — builds the Google consent URL. Exported for unit testing. */
function buildGoogleAuthUrl({ clientId, redirectUri, state }) {
  const q = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    prompt: 'select_account',
    state: state || '',
  });
  return `${GOOGLE_AUTH_URL}?${q.toString()}`;
}

async function exchangeCodeForTokens(code, redirectUri) {
  const res = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }),
  });
  if (!res.ok) {
    const t = await res.text().catch(() => '');
    throw new Error(`token exchange failed: ${res.status} ${t.slice(0, 120)}`);
  }
  return res.json();
}

async function fetchGoogleUserinfo(accessToken) {
  const res = await fetch(GOOGLE_USERINFO_URL, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`userinfo failed: ${res.status}`);
  return res.json(); // { sub, email, email_verified, name, picture }
}

// ---------------------------------------------------------------- app
const app = express();
app.set('trust proxy', 1);

const allowedOrigins = (() => {
  const set = new Set(['http://localhost:3000', 'http://localhost:8080', 'http://127.0.0.1:5500']);
  try { set.add(new URL(PWA_URL).origin); } catch (e) { /* ignore */ }
  return set;
})();

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.has(origin)) return cb(null, true);
    return cb(new Error('CORS: origin not allowed'));
  },
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: false })); // JazzCash posts its result as a form

// ---------------------------------------------------------------- db
const mongo = new MongoClient(MONGODB_URI);
let db, users, sessions, syncdata, payments;

async function initDb() {
  await mongo.connect();
  db = mongo.db(); // db name comes from MONGODB_URI path (e.g. /paperstock)
  users = db.collection('users');
  sessions = db.collection('sessions');
  syncdata = db.collection('syncdata');
  payments = db.collection('payments');
  await users.createIndex({ googleId: 1 }, { unique: true });
  await sessions.createIndex({ tokenHash: 1 }, { unique: true });
  await sessions.createIndex({ userId: 1 });
  // auto-remove expired sessions (best effort; middleware also checks expiry)
  await sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  await syncdata.createIndex({ userId: 1 }, { unique: true });
  await payments.createIndex({ txnRefNo: 1 }, { unique: true });
  await payments.createIndex({ userId: 1 });
  console.log('[db] connected, indexes ready');
}

// ---------------------------------------------------------------- auth middleware
async function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const m = h.match(/^Bearer\s+(.+)$/i);
    if (!m) return res.status(401).json({ error: 'missing token' });
    const tokenHash = sha256hex(m[1].trim());
    const s = await sessions.findOne({ tokenHash });
    if (!s || !s.expiresAt || s.expiresAt.getTime() < Date.now()) {
      return res.status(401).json({ error: 'invalid or expired session' });
    }
    req.userId = s.userId;
    next();
  } catch (e) {
    console.error('[auth] error', e.message);
    res.status(500).json({ error: 'auth error' });
  }
}

// ---------------------------------------------------------------- routes
app.get('/healthz', (req, res) => res.json({ ok: true }));

app.get('/', (req, res) => res.send('PaperPilot API — ok. See /healthz'));

app.get('/auth/google', (req, res) => {
  const redirectUri = `${SERVER_URL}/auth/google/callback`;
  const state = crypto.randomBytes(8).toString('hex');
  res.redirect(302, buildGoogleAuthUrl({ clientId: GOOGLE_CLIENT_ID, redirectUri, state }));
});

app.get('/auth/google/callback', async (req, res) => {
  const redirectUri = `${SERVER_URL}/auth/google/callback`;
  try {
    const { code, error } = req.query;
    if (error || !code) throw new Error(`oauth error: ${error || 'missing code'}`);

    const tokens = await exchangeCodeForTokens(code, redirectUri);
    if (!tokens.access_token) throw new Error('no access_token in token response');
    const info = await fetchGoogleUserinfo(tokens.access_token);
    if (!info.sub || !info.email) throw new Error('incomplete userinfo');

    const now = new Date();
    const upd = {
      googleId: info.sub,
      email: info.email,
      name: info.name || info.email.split('@')[0],
      picture: info.picture || '',
      lastLoginAt: now,
    };
    const r = await users.findOneAndUpdate(
      { googleId: info.sub },
      { $set: upd, $setOnInsert: { plan: 'free', planExpiresAt: null, createdAt: now } },
      { upsert: true, returnDocument: 'after' }
    );
    const user = r.value;
    console.log('[auth] login ok for user', String(user._id));

    const rawToken = crypto.randomBytes(32).toString('hex');
    await sessions.insertOne({
      tokenHash: sha256hex(rawToken),
      userId: user._id,
      createdAt: now,
      expiresAt: new Date(now.getTime() + SESSION_DAYS * 24 * 3600 * 1000),
    });

    res.redirect(302, `${PWA_URL}/#token=${rawToken}`);
  } catch (e) {
    console.error('[auth] callback failed:', e.message);
    res.redirect(302, `${PWA_URL}/#auth=error`);
  }
});

app.get('/api/me', auth, async (req, res) => {
  const u = await users.findOne({ _id: new ObjectId(req.userId) }, { projection: { email: 1, name: 1, picture: 1, plan: 1, planExpiresAt: 1 } });
  if (!u) return res.status(404).json({ error: 'user not found' });
  res.json({ email: u.email, name: u.name, picture: u.picture, plan: u.plan || 'free', planExpiresAt: u.planExpiresAt || null });
});

app.get('/api/data', auth, async (req, res) => {
  const doc = await syncdata.findOne({ userId: new ObjectId(req.userId) });
  if (!doc) return res.json({ data: null, updatedAt: null });
  res.json({ data: doc.data, updatedAt: doc.updatedAt });
});

app.post('/api/data', auth, async (req, res) => {
  const { data } = req.body || {};
  if (!data || typeof data !== 'object') return res.status(400).json({ error: 'missing data object' });
  const updatedAt = new Date();
  await syncdata.updateOne(
    { userId: new ObjectId(req.userId) },
    { $set: { data, updatedAt } },
    { upsert: true }
  );
  res.json({ updatedAt });
});

app.post('/api/logout', auth, async (req, res) => {
  const h = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  await sessions.deleteOne({ tokenHash: sha256hex(h) });
  res.json({ ok: true });
});

// ---------------------------------------------------------------- JazzCash payments
// Plans are one-time purchases (no auto-renew): expiry = now + plan days.
app.post('/api/pay/create', auth, async (req, res) => {
  try {
    if (!JC_CONFIGURED) return res.status(503).json({ error: 'payments not configured' });
    const { plan } = req.body || {};
    const p = jazzcash.PLANS[plan];
    if (!p) return res.status(400).json({ error: 'unknown plan' });

    const txnRefNo = jazzcash.makeTxnRefNo();
    const fields = jazzcash.buildPaymentFields(
      { merchantId: JC.merchantId, password: JC.password, integritySalt: JC.integritySalt, returnUrl: `${SERVER_URL}/api/pay/jazzcash/return` },
      { amountRs: p.amountRs, billRef: txnRefNo, description: p.label, txnRefNo, userId: req.userId }
    );
    await payments.insertOne({
      txnRefNo, userId: new ObjectId(req.userId), plan,
      amountRs: p.amountRs, status: 'pending', createdAt: new Date(),
    });
    console.log('[pay] created', txnRefNo, plan);
    res.json({ postUrl: JC_POST_URL, fields, txnRefNo, amountRs: p.amountRs });
  } catch (e) {
    console.error('[pay] create failed:', e.message);
    res.status(500).json({ error: 'could not start payment' });
  }
});

// JazzCash calls this (server-to-server form POST) after the user pays.
// pp_ResponseCode "000" = success.
app.post('/api/pay/jazzcash/return', async (req, res) => {
  const b = req.body || {};
  const okPage = (title, msg) =>
    res.send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title></head>` +
      `<body style="font-family:sans-serif;text-align:center;padding:48px 16px"><h2>${title}</h2><p>${msg}</p><p>App mein wapas jayein.</p></body></html>`);
  try {
    if (!jazzcash.verifyReturnHash(b, JC.integritySalt)) {
      console.error('[pay] return hash mismatch for', b.pp_TxnRefNo);
      return okPage('Tasdeeq nakaam', 'Payment ki tasdeeq nahi ho saki. Support se rabta karein.');
    }
    const pay = await payments.findOne({ txnRefNo: b.pp_TxnRefNo });
    if (!pay) {
      console.error('[pay] unknown txnRefNo', b.pp_TxnRefNo);
      return okPage('Record nahi mila', 'Is payment ka record nahi mila. Support se rabta karein.');
    }
    if (pay.status === 'success') return okPage('Kamyab!', 'Premium pehle hi active ho chuka hai.');
    if (String(b.pp_ResponseCode) === '000') {
      const p = jazzcash.PLANS[pay.plan];
      const expiresAt = new Date(Date.now() + p.days * 86400000);
      await payments.updateOne({ _id: pay._id }, { $set: { status: 'success', paidAt: new Date(), ppResponse: String(b.pp_ResponseCode) } });
      await users.updateOne({ _id: pay.userId }, { $set: { plan: 'premium', planExpiresAt: expiresAt } });
      console.log('[pay] SUCCESS', pay.txnRefNo, pay.plan);
      return okPage('Payment kamyab! 🎉', 'Premium active ho gaya hai.');
    }
    await payments.updateOne({ _id: pay._id }, { $set: { status: 'failed', ppResponse: String(b.pp_ResponseCode || ''), ppMessage: String(b.pp_ResponseMessage || '').slice(0, 200) } });
    console.log('[pay] FAILED', pay.txnRefNo, b.pp_ResponseCode, b.pp_ResponseMessage);
    return okPage('Payment nakaam', 'Dobara koshish karein.');
  } catch (e) {
    console.error('[pay] return handler error:', e.message);
    return okPage('Error', 'Kuch ghalat ho gaya. Support se rabta karein.');
  }
});

// App polls this while the user is on the JazzCash page.
app.get('/api/pay/status', auth, async (req, res) => {
  const txnRefNo = String(req.query.txnRefNo || '');
  const pay = await payments.findOne({ txnRefNo, userId: new ObjectId(req.userId) });
  if (!pay) return res.status(404).json({ error: 'payment not found' });
  const u = await users.findOne({ _id: new ObjectId(req.userId) }, { projection: { plan: 1, planExpiresAt: 1 } });
  res.json({ status: pay.status, plan: u ? (u.plan || 'free') : 'free', planExpiresAt: u ? (u.planExpiresAt || null) : null });
});

// ---------------------------------------------------------------- start
if (require.main === module) {
  initDb()
    .then(() => app.listen(PORT, () => console.log(`[server] listening on :${PORT}`)))
    .catch((e) => { console.error('[db] connect failed:', e.message); process.exit(1); });
}

module.exports = { app, buildGoogleAuthUrl, sha256hex };
