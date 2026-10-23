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
 *   GET  /api/pay/plans         -> plan list (from jazzcash.PLANS)
 *   GET  /api/pay/manual/config (auth) -> manual payment numbers + plans
 *   POST /api/pay/manual        (auth) -> user submits a manual payment (txn ID)
 *   GET  /api/pay/manual/mine   (auth) -> user's own manual payment requests
 *   GET  /api/admin/payments    (admin key) -> payment requests list
 *   POST /api/admin/payments/:id/activate (admin key) -> activate premium
 *   POST /api/admin/payments/:id/reject   (admin key) -> reject request
 *   GET  /api/safepay/config    (auth) -> { configured, plans } for the Pay button
 *   POST /api/safepay/checkout  (auth) -> create Safepay session, returns Checkout URL
 *   GET  /api/safepay/status    (auth) -> poll payment; settles via Safepay reporter
 *   POST /api/safepay/webhook   -> Safepay events (HMAC-SHA512 verified, ack-first)
 *   GET  /pay/safepay/done|cancel -> hosted-checkout return pages
 *   GET  /admin                 -> owner admin page (admin.html)
 *   GET  /privacy               -> privacy policy page
 *   GET  /terms                 -> terms of service page
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
const path = require('path');
const jazzcash = require('./jazzcash');
const notify = require('./notify');
const safepay = require('./safepay');

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

// Manual payments (user sends money to the owner's own account — JazzCash,
// Easypaisa, NayaPay, SadaPay or a bank account — and submits the transaction
// ID in the app; owner approves in /admin).
// The numbers are PUBLIC (customers must see them to pay) — set on Render.
const MANUAL_PAY = {
  jazzcashNumber: process.env.PAY_JAZZCASH_NUMBER || '',
  jazzcashTitle: process.env.PAY_JAZZCASH_TITLE || '',
  easypaisaNumber: process.env.PAY_EASYPAISA_NUMBER || '',
  easypaisaTitle: process.env.PAY_EASYPAISA_TITLE || '',
  nayapayNumber: process.env.PAY_NAYAPAY_NUMBER || '',
  nayapayTitle: process.env.PAY_NAYAPAY_TITLE || '',
  sadapayNumber: process.env.PAY_SADAPAY_NUMBER || '',
  sadapayTitle: process.env.PAY_SADAPAY_TITLE || '',
  bankName: process.env.PAY_BANK_NAME || '',
  bankNumber: process.env.PAY_BANK_NUMBER || '', // account number or IBAN
  bankTitle: process.env.PAY_BANK_TITLE || '',
};

/** Configured manual payment methods: [{ key, label, number, title }]. */
function manualMethods() {
  const list = [];
  const add = (key, label, number, title) => { if (number) list.push({ key, label, number, title: title || '' }); };
  add('jazzcash', 'JazzCash', MANUAL_PAY.jazzcashNumber, MANUAL_PAY.jazzcashTitle);
  add('easypaisa', 'Easypaisa', MANUAL_PAY.easypaisaNumber, MANUAL_PAY.easypaisaTitle);
  add('nayapay', 'NayaPay', MANUAL_PAY.nayapayNumber, MANUAL_PAY.nayapayTitle);
  add('sadapay', 'SadaPay', MANUAL_PAY.sadapayNumber, MANUAL_PAY.sadapayTitle);
  add('bank', MANUAL_PAY.bankName || 'Bank Transfer', MANUAL_PAY.bankNumber, MANUAL_PAY.bankTitle);
  return list;
}
const MANUAL_CONFIGURED = manualMethods().length > 0;
if (!MANUAL_CONFIGURED) console.warn('[config] Manual payment numbers not set — set PAY_JAZZCASH_NUMBER / PAY_EASYPAISA_NUMBER / PAY_NAYAPAY_NUMBER / PAY_SADAPAY_NUMBER / PAY_BANK_NUMBER.');

// Owner admin (for /admin page + /api/admin/*). Long random secret, Render only.
const ADMIN_KEY = process.env.ADMIN_KEY || '';
if (!ADMIN_KEY) console.warn('[config] ADMIN_KEY not set — /api/admin/* will return 503.');

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
  // The owner admin page (/admin) is served from this server's own origin —
  // without this entry the browser's CORS check rejects its POST calls
  // (Approve/Reject) with HTTP 500 "CORS: origin not allowed" (hit 2026-10-23).
  try { if (SERVER_URL) set.add(new URL(SERVER_URL).origin); } catch (e) { /* ignore */ }
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
let db, users, sessions, syncdata, payments, logincodes;

async function initDb() {
  await mongo.connect();
  db = mongo.db(); // db name comes from MONGODB_URI path (e.g. /paperstock)
  users = db.collection('users');
  sessions = db.collection('sessions');
  syncdata = db.collection('syncdata');
  payments = db.collection('payments');
  logincodes = db.collection('logincodes');
  await logincodes.createIndex({ email: 1 }, { unique: true });
  await logincodes.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  await users.createIndex({ googleId: 1 }, { unique: true });
  await sessions.createIndex({ tokenHash: 1 }, { unique: true });
  await sessions.createIndex({ userId: 1 });
  // auto-remove expired sessions (best effort; middleware also checks expiry)
  await sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  await syncdata.createIndex({ userId: 1 }, { unique: true });
  await payments.createIndex({ txnRefNo: 1 }, { unique: true });
  await users.createIndex({ uid: 1 }, { unique: true, sparse: true }).catch(() => {});
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

// ---------------------------------------------------------------- admin + premium helpers
function adminOnly(req, res, next) {
  if (!ADMIN_KEY) return res.status(503).json({ error: 'admin not configured' });
  const key = String(req.headers['x-admin-key'] || '');
  const a = Buffer.from(key);
  const b = Buffer.from(ADMIN_KEY);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'invalid admin key' });
  }
  next();
}

/**
 * Sets plan=premium for a user. If the user is already premium and the plan
 * has not expired yet, the new plan extends from the current expiry
 * (renewals stack); otherwise it starts from now.
 * Returns the new expiresAt Date.
 */
async function activatePremium(userId, planKey) {
  const p = jazzcash.PLANS[planKey];
  if (!p) throw new Error('unknown plan');
  const u = await users.findOne({ _id: new ObjectId(userId) }, { projection: { plan: 1, planExpiresAt: 1 } });
  const now = Date.now();
  const current = u && u.plan === 'premium' && u.planExpiresAt && new Date(u.planExpiresAt).getTime() > now
    ? new Date(u.planExpiresAt).getTime()
    : now;
  const expiresAt = new Date(current + p.days * 86400000);
  await users.updateOne({ _id: new ObjectId(userId) }, { $set: { plan: 'premium', planExpiresAt: expiresAt } });
  return expiresAt;
}

function publicPlans() {
  return Object.entries(jazzcash.PLANS).map(([key, p]) => ({
    key, amountRs: p.amountRs, days: p.days, label: p.label,
  }));
}

// ---------------------------------------------------------------- routes
app.get('/healthz', (req, res) => res.json({ ok: true }));

app.get('/', (req, res) => res.send('ReamBook API — ok. See /healthz'));

// ReamBook APK download (in-app update channel). The binary rides in the
// ReamBook logo for share previews (WhatsApp card image) — same base64
// text trick as the APK, because repo pushes are text-only.
let _logoBuf = null;
app.get('/logo.png', (req, res) => {
  try {
    if (!_logoBuf) {
      const b64 = require('fs').readFileSync(path.join(__dirname, 'logo.b64'), 'utf8').replace(/\s+/g, '');
      _logoBuf = Buffer.from(b64, 'base64');
    }
    res.set('Content-Type', 'image/png');
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(_logoBuf);
  } catch (e) { res.status(404).send('no logo'); }
});
// repo as base64 text (app-apk.b64) because repo pushes are text-only.
let _apkBuf = null;
app.get(['/app/ReamBook.apk', '/app/PaperFlow.apk'], (req, res) => {
  try {
    if (!_apkBuf) {
      const b64 = require('fs').readFileSync(path.join(__dirname, 'app-apk.b64'), 'utf8').replace(/\s+/g, '');
      _apkBuf = Buffer.from(b64, 'base64');
    }
    res.set('Content-Type', 'application/vnd.android.package-archive');
    res.set('Content-Disposition', 'attachment; filename="ReamBook.apk"');
    return res.send(_apkBuf);
  } catch (e) { return res.status(404).send('not available'); }
});

app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'privacy.html')));
app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'terms.html')));

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
    // If this email already has an account (e.g. created via email-code
    // login), attach the Google id to THAT account so the data stays unified.
    const byGoogle = await users.findOne({ googleId: info.sub });
    if (!byGoogle) {
      const byEmail = await users.findOne({ email: info.email });
      if (byEmail) await users.updateOne({ _id: byEmail._id }, { $set: { googleId: info.sub } });
    }
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

    const rawToken = await issueSession(user._id, now);

    res.redirect(302, `${PWA_URL}/#token=${rawToken}`);
  } catch (e) {
    console.error('[auth] callback failed:', e.message);
    res.redirect(302, `${PWA_URL}/#auth=error`);
  }
});

app.get('/api/me', auth, async (req, res) => {
  const u = await users.findOne({ _id: new ObjectId(req.userId) }, { projection: { email: 1, name: 1, picture: 1, plan: 1, planExpiresAt: 1, uid: 1 } });
  if (!u) return res.status(404).json({ error: 'user not found' });
  const uid = await ensureUid(u);
  res.json({ email: u.email, name: u.name, picture: u.picture, plan: u.plan || 'free', planExpiresAt: u.planExpiresAt || null, uid: uid || '' });
});

// every user gets a short public ID (shown as RB-123456) — copyable in the app,
// attached to payment claims and searchable in the owner admin page.
async function ensureUid(u) {
  if (!u) return null;
  if (u.uid) return u.uid;
  for (let i = 0; i < 8; i++) {
    const code = String(Math.floor(100000 + Math.random() * 900000));
    try {
      const r = await users.updateOne({ _id: u._id, uid: { $exists: false } }, { $set: { uid: code } });
      if (r.modifiedCount) return code;
      const fresh = await users.findOne({ _id: u._id }, { projection: { uid: 1 } });
      if (fresh && fresh.uid) return fresh.uid;
    } catch (e) { /* duplicate uid — retry with a new code */ }
  }
  return null;
}

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

// ---------------------------------------------------------------- email-code login
// The Android wrapper sends external hosts to Chrome, so Google OAuth can
// never complete inside the app. Instead: the user types their email in the
// app, we email a 6-digit code, and the app exchanges it for the SAME kind
// of 365-day session Google login creates. Codes are stored hashed, expire
// in 10 minutes, allow max 5 attempts, and are rate-limited per email + IP.
async function issueSession(userId, now) {
  const rawToken = crypto.randomBytes(32).toString('hex');
  await sessions.insertOne({
    tokenHash: sha256hex(rawToken),
    userId,
    createdAt: now,
    expiresAt: new Date(now.getTime() + SESSION_DAYS * 24 * 3600 * 1000),
  });
  return rawToken;
}

async function findOrCreateUserByEmail(email) {
  const now = new Date();
  const existing = await users.findOne({ email });
  if (existing) {
    await users.updateOne({ _id: existing._id }, { $set: { lastLoginAt: now } });
    return existing;
  }
  const doc = {
    googleId: 'email:' + email,
    email,
    name: email.split('@')[0],
    picture: '',
    plan: 'free',
    planExpiresAt: null,
    createdAt: now,
    lastLoginAt: now,
  };
  try {
    const r = await users.insertOne(doc);
    doc._id = r.insertedId;
    return doc;
  } catch (e) {
    // unique-googleId race: someone created it first — just read it back
    const again = await users.findOne({ email });
    if (again) return again;
    throw e;
  }
}

const CODE_TTL_MS = 10 * 60 * 1000;
const CODE_RESEND_MS = 60 * 1000;
const CODE_MAX_PER_HOUR = 5;
const CODE_MAX_ATTEMPTS = 5;
const ipHits = new Map(); // ip -> [timestamps in the last hour]
function ipFlooded(ip) {
  const now = Date.now();
  const arr = (ipHits.get(ip) || []).filter((t) => now - t < 3600000);
  arr.push(now);
  ipHits.set(ip, arr);
  if (ipHits.size > 5000) ipHits.clear(); // crude memory guard on a tiny server
  return arr.length > 100;
}

app.post('/api/auth/code/request', async (req, res) => {
  try {
    const email = String((req.body || {}).email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (!notify.mailSenderConfigured()) {
      return res.status(503).json({ error: 'Email login is not set up yet. Please try again later.' });
    }
    if (ipFlooded(req.ip)) {
      return res.status(429).json({ error: 'Too many requests — please try again later.' });
    }
    const now = new Date();
    const existing = await logincodes.findOne({ email });
    let sends = [];
    if (existing) {
      if (now.getTime() - new Date(existing.lastSentAt).getTime() < CODE_RESEND_MS) {
        return res.status(429).json({ error: 'A code was just sent — wait a minute, check your inbox, then try again.' });
      }
      sends = (existing.sends || []).filter((t) => now.getTime() - new Date(t).getTime() < 3600000);
      if (sends.length >= CODE_MAX_PER_HOUR) {
        return res.status(429).json({ error: 'Too many codes requested — please try again in an hour.' });
      }
    }
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    sends.push(now);
    await logincodes.updateOne(
      { email },
      { $set: { email, codeHash: sha256hex(email + ':' + code), expiresAt: new Date(now.getTime() + CODE_TTL_MS), attempts: 0, lastSentAt: now, sends } },
      { upsert: true }
    );
    try {
      await notify.sendLoginCode(email, code);
    } catch (e) {
      // Never leave a live code behind that the user never received.
      await logincodes.deleteOne({ email });
      console.error('[auth] login code send failed:', e.message);
      return res.status(502).json({ error: 'Could not send the email — please try again.' });
    }
    console.log('[auth] login code sent to', email);
    res.json({ ok: true });
  } catch (e) {
    console.error('[auth] code request failed:', e.message);
    res.status(500).json({ error: 'Something went wrong — please try again.' });
  }
});

app.post('/api/auth/code/verify', async (req, res) => {
  try {
    const email = String((req.body || {}).email || '').trim().toLowerCase();
    const code = String((req.body || {}).code || '').trim();
    if (!email || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'Enter the 6-digit code from your email.' });
    }
    if (ipFlooded(req.ip)) {
      return res.status(429).json({ error: 'Too many requests — please try again later.' });
    }
    const invalid = { error: 'Invalid or expired code — request a new one.' };
    const doc = await logincodes.findOne({ email });
    if (!doc || !doc.expiresAt || new Date(doc.expiresAt).getTime() < Date.now()) {
      return res.status(400).json(invalid);
    }
    if ((doc.attempts || 0) >= CODE_MAX_ATTEMPTS) {
      await logincodes.deleteOne({ email });
      return res.status(400).json(invalid);
    }
    const given = Buffer.from(sha256hex(email + ':' + code));
    const stored = Buffer.from(String(doc.codeHash || ''));
    if (given.length !== stored.length || !crypto.timingSafeEqual(given, stored)) {
      await logincodes.updateOne({ email }, { $inc: { attempts: 1 } });
      return res.status(400).json(invalid);
    }
    await logincodes.deleteOne({ email });
    const user = await findOrCreateUserByEmail(email);
    const rawToken = await issueSession(user._id, new Date());
    console.log('[auth] code login ok for user', String(user._id));
    res.json({ token: rawToken, email: user.email, name: user.name || '' });
  } catch (e) {
    console.error('[auth] code verify failed:', e.message);
    res.status(500).json({ error: 'Login failed — please try again.' });
  }
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
      const pu = await users.findOne({ _id: pay.userId }, { projection: { email: 1 } });
      notify.notifyActivated({
        userEmail: pu ? pu.email : '', plan: pay.plan, amountRs: pay.amountRs,
        expiresAt, via: 'JazzCash gateway (automatic)',
      }).catch(() => {});
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

// ---------------------------------------------------------------- manual payments
app.get('/api/pay/plans', (req, res) => res.json({ plans: publicPlans() }));

// Numbers + plans the app shows on the Subscribe screen. Auth required so the
// numbers are only shown to logged-in customers.
app.get('/api/pay/manual/config', auth, (req, res) => {
  res.json({
    configured: MANUAL_CONFIGURED,
    methods: manualMethods(),
    // legacy fields, kept for older app versions
    jazzcash: MANUAL_PAY.jazzcashNumber ? { number: MANUAL_PAY.jazzcashNumber, title: MANUAL_PAY.jazzcashTitle } : null,
    easypaisa: MANUAL_PAY.easypaisaNumber ? { number: MANUAL_PAY.easypaisaNumber, title: MANUAL_PAY.easypaisaTitle } : null,
    plans: publicPlans(),
  });
});

// User submits a manual payment: they already sent the money to the owner's
// number and now give us the transaction ID from their JazzCash/Easypaisa app.
app.post('/api/pay/manual', auth, async (req, res) => {
  try {
    if (!MANUAL_CONFIGURED) return res.status(503).json({ error: 'manual payments not configured' });
    const { plan, method, txnId, senderName, senderNumber, slip } = req.body || {};
    const p = jazzcash.PLANS[plan];
    if (!p) return res.status(400).json({ error: 'unknown plan' });
    const m = manualMethods().find((x) => x.key === method);
    if (!m) return res.status(400).json({ error: 'unknown or unavailable method' });
    const cleanTxn = String(txnId || '').trim().toUpperCase().replace(/\s+/g, '');
    if (!/^[A-Z0-9-]{5,40}$/.test(cleanTxn)) return res.status(400).json({ error: 'invalid transaction id' });
    const txnRefNo = `MAN-${cleanTxn}`;

    let slipData = null;
    if (slip != null && slip !== '') {
      if (typeof slip !== 'string' || !slip.startsWith('data:image/') || slip.length > 2500000) {
        return res.status(400).json({ error: 'slip photo is too large or invalid' });
      }
      slipData = slip;
    }

    const existing = await payments.findOne({ txnRefNo });
    if (existing) return res.status(409).json({ error: 'this transaction id was already submitted' });

    await payments.insertOne({
      txnRefNo, userId: new ObjectId(req.userId), plan,
      amountRs: p.amountRs, status: 'manual_pending', kind: 'manual', method, methodLabel: m.label,
      senderName: String(senderName || '').slice(0, 80),
      senderNumber: String(senderNumber || '').slice(0, 30),
      slip: slipData,
      createdAt: new Date(),
    });
    console.log('[pay-manual] request', txnRefNo, plan, method);

    const u = await users.findOne({ _id: new ObjectId(req.userId) }, { projection: { email: 1, name: 1 } });
    notify.notifyManualRequest({
      userEmail: u ? u.email : '', userName: u ? u.name : '',
      plan, amountRs: p.amountRs, method, txnRefNo,
      senderName: String(senderName || ''), senderNumber: String(senderNumber || ''),
      adminUrl: SERVER_URL ? `${SERVER_URL}/admin` : '',
    }).catch(() => {});

    res.json({ ok: true, status: 'manual_pending', txnRefNo });
  } catch (e) {
    console.error('[pay-manual] submit failed:', e.message);
    res.status(500).json({ error: 'could not submit payment' });
  }
});

// The user's own manual payment requests (for the status list in the app).
app.get('/api/pay/manual/mine', auth, async (req, res) => {
  const list = await payments
    .find({ userId: new ObjectId(req.userId), kind: 'manual' })
    .sort({ createdAt: -1 })
    .limit(10)
    .toArray();
  res.json({
    payments: list.map((d) => ({
      txnRefNo: d.txnRefNo, plan: d.plan, amountRs: d.amountRs,
      status: d.status, method: d.method, createdAt: d.createdAt, paidAt: d.paidAt || null,
    })),
  });
});

// ---------------------------------------------------------------- owner admin
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

app.get('/api/admin/payments', adminOnly, async (req, res) => {
  const q = String(req.query.q || '').trim();
  let filter;
  if (q) {
    const or = [{ txnRefNo: new RegExp(escapeRegExp(q.replace(/^MAN-/i, '')), 'i') }];
    const digits = q.replace(/^RB-/i, '').replace(/\D/g, '');
    const uq = [{ email: new RegExp(escapeRegExp(q), 'i') }, { name: new RegExp(escapeRegExp(q), 'i') }];
    if (digits) uq.push({ uid: digits });
    const us = await users.find({ $or: uq }, { projection: { _id: 1 } }).limit(50).toArray();
    if (us.length) or.push({ userId: { $in: us.map((x) => x._id) } });
    filter = { $or: or };
  } else {
    filter = { status: String(req.query.status || 'manual_pending') };
  }
  const list = await payments.find(filter).sort({ createdAt: -1 }).limit(100).toArray();
  const out = [];
  for (const d of list) {
    const u = await users.findOne({ _id: d.userId }, { projection: { email: 1, name: 1, plan: 1, planExpiresAt: 1, uid: 1 } });
    out.push({
      id: String(d._id), txnRefNo: d.txnRefNo, plan: d.plan, amountRs: d.amountRs,
      status: d.status, kind: d.kind || 'gateway', method: d.methodLabel || d.method || '',
      senderName: d.senderName || '', senderNumber: d.senderNumber || '',
      hasSlip: !!d.slip,
      createdAt: d.createdAt, paidAt: d.paidAt || null,
      userEmail: u ? u.email : '', userName: u ? u.name : '', userUid: u ? (u.uid || '') : '',
      userPlan: u ? (u.plan || 'free') : '', userPlanExpiresAt: u ? (u.planExpiresAt || null) : null,
    });
  }
  res.json({ payments: out });
});

app.get('/api/admin/payments/:id/slip', adminOnly, async (req, res) => {
  try {
    const d = await payments.findOne({ _id: new ObjectId(req.params.id) }, { projection: { slip: 1 } });
    if (!d || !d.slip) return res.status(404).json({ error: 'no slip photo for this payment' });
    res.json({ slip: d.slip });
  } catch (e) { res.status(400).json({ error: 'bad id' }); }
});

app.post('/api/admin/payments/:id/activate', adminOnly, async (req, res) => {
  try {
    const pay = await payments.findOne({ _id: new ObjectId(req.params.id) });
    if (!pay) return res.status(404).json({ error: 'payment not found' });
    if (pay.status === 'success') return res.status(409).json({ error: 'already activated' });
    if (pay.status !== 'manual_pending' && pay.status !== 'rejected') return res.status(409).json({ error: `cannot activate a payment with status ${pay.status}` });

    const expiresAt = await activatePremium(pay.userId, pay.plan);
    await payments.updateOne({ _id: pay._id }, { $set: { status: 'success', paidAt: new Date(), activatedBy: 'owner-admin' } });
    console.log('[pay-manual] ACTIVATED', pay.txnRefNo, pay.plan, 'until', expiresAt.toISOString());

    const u = await users.findOne({ _id: pay.userId }, { projection: { email: 1 } });
    notify.notifyActivated({
      userEmail: u ? u.email : '', plan: pay.plan, amountRs: pay.amountRs,
      expiresAt, via: `manual ${pay.method || ''} (owner approved)`,
    }).catch(() => {});

    res.json({ ok: true, expiresAt });
  } catch (e) {
    console.error('[pay-manual] activate failed:', e.message);
    res.status(500).json({ error: 'could not activate' });
  }
});

app.post('/api/admin/payments/:id/reject', adminOnly, async (req, res) => {
  try {
    const pay = await payments.findOne({ _id: new ObjectId(req.params.id) });
    if (!pay) return res.status(404).json({ error: 'payment not found' });
    if (pay.status !== 'manual_pending') return res.status(409).json({ error: `cannot reject a payment with status ${pay.status}` });
    await payments.updateOne(
      { _id: pay._id },
      { $set: { status: 'rejected', adminNote: String((req.body || {}).note || '').slice(0, 200) } }
    );
    console.log('[pay-manual] REJECTED', pay.txnRefNo);
    res.json({ ok: true });
  } catch (e) {
    console.error('[pay-manual] reject failed:', e.message);
    res.status(500).json({ error: 'could not reject' });
  }
});

// ---------------------------------------------------------------- Safepay payments
// Automatic card/wallet checkout (see safepay.js). Dormant until the owner
// sets SAFEPAY_* on Render: config reports configured:false, checkout 503s.
safepay.registerSafepay(app, {
  auth,
  getPayments: () => payments,
  getUsers: () => users,
  activatePremium,
  notifyActivated: (o) => notify.notifyActivated(o).catch(() => {}),
  plans: jazzcash.PLANS,
  publicPlans,
  serverUrl: SERVER_URL,
});
if (!safepay.getConfig().configured) console.warn('[config] Safepay not configured — set SAFEPAY_SECRET_KEY / SAFEPAY_API_KEY (SAFEPAY_MODE=sandbox|live).');

// ---------------------------------------------------------------- start
if (require.main === module) {
  initDb()
    .then(() => app.listen(PORT, () => console.log(`[server] listening on :${PORT}`)))
    .catch((e) => { console.error('[db] connect failed:', e.message); process.exit(1); });
}

module.exports = { app, buildGoogleAuthUrl, sha256hex, publicPlans, manualMethods };
