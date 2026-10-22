'use strict';
/**
 * Safepay (getsafepay.pk) hosted-checkout integration for ReamBook
 * subscriptions — automatic payment -> automatic premium activation.
 *
 * Flow:
 *   1. App (logged in) POST /api/safepay/checkout { plan }
 *      -> server creates a Safepay payment session (tracker) + auth token,
 *         stores a pending payment record keyed by the tracker, and returns
 *         the hosted Checkout URL.
 *   2. User pays on Safepay's page (card / wallet — whatever the merchant
 *      account has enabled). Safepay redirects to /pay/safepay/done.
 *   3. Activation happens through whichever arrives first, both gated by
 *      Safepay's own reporter API (state must be TRACKER_ENDED):
 *        - POST /api/safepay/webhook (HMAC-SHA512 verified, ack 200 first)
 *        - GET  /api/safepay/status (the app polls this after returning)
 *      Activation is idempotent per tracker and stacks via activatePremium.
 *   4. Owner gets the usual activation email (notify.notifyActivated).
 *
 * Verified against the official Safepay docs on 2026-10-22
 * (express-checkout guide, webhooks overview, verify-hmac-signatures):
 *   - Server auth header: X-SFPY-MERCHANT-SECRET: <secret key>
 *   - POST /order/payments/v3/ -> data.tracker.token ("track_...")
 *   - POST /client/passport/v1/token -> data = short-lived token (1 hour)
 *   - Checkout URL: {embedded}/?environment=..&tracker=..&tbt=..&source=..
 *     (embedded host: sandbox.api.getsafepay.com for sandbox,
 *      getsafepay.com for production — same shape @sfpy/node-core builds)
 *   - GET /reporter/api/v1/payments/{tracker} -> data.tracker.state;
 *     "TRACKER_ENDED" means the payment completed successfully.
 *   - Webhooks: header X-SFPY-SIGNATURE = hex HMAC-SHA512 of the JSON
 *     payload with the endpoint's shared secret; event.type is
 *     "payment.succeeded" / "payment.failed"; ack 200 within 10s, before
 *     business logic; multiple webhooks per tracker are normal.
 *
 * Env (set on Render by the owner; never in code or chat):
 *   SAFEPAY_SECRET_KEY, SAFEPAY_API_KEY, SAFEPAY_WEBHOOK_SECRET,
 *   SAFEPAY_MODE = "sandbox" (default) | "live"
 * Until the keys are set, /api/safepay/config reports configured:false and
 * checkout returns 503 — the app hides the Pay button.
 */
const crypto = require('crypto');

const HOSTS = {
  sandbox: { api: 'https://sandbox.api.getsafepay.com', embedded: 'https://sandbox.api.getsafepay.com/embedded/', env: 'sandbox' },
  live: { api: 'https://api.getsafepay.com', embedded: 'https://getsafepay.com/embedded/', env: 'production' },
};

/** Reads Safepay config from an env-like object (process.env by default). */
function getConfig(env) {
  const e = env || process.env;
  const mode = String(e.SAFEPAY_MODE || 'sandbox').trim().toLowerCase() === 'live' ? 'live' : 'sandbox';
  const secretKey = String(e.SAFEPAY_SECRET_KEY || '').trim();
  const apiKey = String(e.SAFEPAY_API_KEY || '').trim();
  const webhookSecret = String(e.SAFEPAY_WEBHOOK_SECRET || '').trim();
  return {
    mode, secretKey, apiKey, webhookSecret,
    configured: Boolean(secretKey && apiKey),
    host: HOSTS[mode],
  };
}

/** Plan price in paisa (Safepay charges the lowest denomination). */
function planToPaisa(planDef) {
  return Math.round(planDef.amountRs * 100);
}

/** Builds the hosted Checkout URL exactly like the official SDK does. */
function buildCheckoutUrl(cfg, { tracker, tbt, source, redirectUrl, cancelUrl, userId }) {
  const params = new URLSearchParams();
  params.set('environment', cfg.host.env);
  params.set('tracker', tracker);
  params.set('tbt', tbt);
  if (source) params.set('source', source);
  if (redirectUrl) params.set('redirect_url', redirectUrl);
  if (cancelUrl) params.set('cancel_url', cancelUrl);
  if (userId) params.set('user_id', userId);
  return cfg.host.embedded + '?' + params.toString();
}

/**
 * Verifies a webhook signature per the docs: HMAC-SHA512 (hex) over the
 * JSON string of the payload, keyed with the endpoint's shared secret.
 * `payload` may be the raw string or the parsed object.
 */
function verifyWebhookSignature(payload, signature, secret) {
  if (!payload || !signature || !secret) return false;
  const data = Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload), 'utf8');
  const hash = crypto.createHmac('sha512', secret).update(data).digest('hex');
  const a = Buffer.from(hash.toLowerCase());
  const b = Buffer.from(String(signature).trim().toLowerCase());
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/** Pulls the tracker token out of a webhook event, tolerating shape drift. */
function extractTracker(event) {
  if (!event || typeof event !== 'object') return '';
  const cands = [
    event.data && event.data.tracker && event.data.tracker.token,
    event.data && event.data.tracker,
    event.tracker && event.tracker.token,
    event.tracker,
    event.data && event.data.token,
  ];
  for (const c of cands) {
    if (typeof c === 'string' && c.startsWith('track_')) return c;
  }
  return '';
}

/** Thin Safepay REST client. `fetchImpl` is injectable for tests. */
function createClient(cfg, fetchImpl) {
  const doFetch = fetchImpl || fetch;
  const headers = { 'X-SFPY-MERCHANT-SECRET': cfg.secretKey, 'Content-Type': 'application/json' };
  async function call(method, pathStr, body) {
    const r = await doFetch(cfg.host.api + pathStr, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    });
    let j = null;
    try { j = await r.json(); } catch (e) { /* non-JSON response */ }
    if (!r.ok) {
      let msg = '';
      try {
        msg = (j && j.status && (j.status.message || (Array.isArray(j.status.errors) ? j.status.errors.join('; ') : ''))) || (j && j.message) || '';
      } catch (e) { /* keep msg empty */ }
      throw new Error(`safepay ${method} ${pathStr} -> HTTP ${r.status}${msg ? ': ' + msg : ''}`);
    }
    return j;
  }
  return {
    /** Creates a payment session; returns the tracker token ("track_..."). */
    async createSession({ planDef, metadata }) {
      const j = await call('POST', '/order/payments/v3/', {
        merchant_api_key: cfg.apiKey,
        intent: 'CYBERSOURCE',
        mode: 'payment',
        entry_mode: 'raw',
        currency: 'PKR',
        amount: planToPaisa(planDef),
        metadata,
        include_fees: false,
      });
      const token = j && j.data && j.data.tracker && j.data.tracker.token;
      if (!token) throw new Error('safepay session: no tracker token in response');
      return token;
    },
    /** Short-lived auth token used in the Checkout URL. */
    async createPassportToken() {
      const j = await call('POST', '/client/passport/v1/token', {});
      if (!j || typeof j.data !== 'string' || !j.data) throw new Error('safepay passport: no token in response');
      return j.data;
    },
    /** Full payment/tracker state from the reporter API. */
    async fetchPayment(tracker) {
      return call('GET', '/reporter/api/v1/payments/' + encodeURIComponent(tracker));
    },
  };
}

/**
 * Registers the Safepay routes on the express app.
 * deps: {
 *   auth, getPayments(), getUsers(), activatePremium(userId, planKey),
 *   notifyActivated(obj), plans, publicPlans(), serverUrl, config?, client?
 * }
 * config/client overrides exist for tests; production passes neither.
 */
function registerSafepay(app, deps) {
  const cfg = deps.config || getConfig();
  const client = deps.client || createClient(cfg);
  const plans = deps.plans;

  /**
   * Reporter-gated, idempotent settlement: only a tracker that Safepay
   * itself reports as TRACKER_ENDED (and that matches one of OUR pending
   * payment records, amount included) can activate premium.
   */
  async function settle(tracker) {
    const payments = deps.getPayments();
    const pay = await payments.findOne({ tracker });
    if (!pay || pay.status === 'success') return pay;
    let remote;
    try { remote = await client.fetchPayment(tracker); } catch (e) {
      console.error('[safepay] reporter check failed for', tracker, e.message);
      return pay;
    }
    const t = remote && remote.data && remote.data.tracker;
    if (!t || t.state !== 'TRACKER_ENDED') return pay;
    const paidAmount = t.purchase_totals && t.purchase_totals.quote_amount && t.purchase_totals.quote_amount.amount;
    if (paidAmount != null && Number(paidAmount) !== planToPaisa(plans[pay.plan])) {
      console.error('[safepay] amount mismatch for', tracker, 'paid', paidAmount, 'expected', planToPaisa(plans[pay.plan]));
      return pay;
    }
    const upd = await payments.updateOne(
      { _id: pay._id, status: { $ne: 'success' } },
      { $set: { status: 'success', paidAt: new Date(), via: 'safepay', sfState: t.state } }
    );
    if (upd && upd.modifiedCount === 1) {
      const expiresAt = await deps.activatePremium(pay.userId, pay.plan);
      console.log('[safepay] SUCCESS', tracker, pay.plan);
      try {
        const u = await deps.getUsers().findOne({ _id: pay.userId }, { projection: { email: 1 } });
        await deps.notifyActivated({
          userEmail: u ? u.email : '', plan: pay.plan, amountRs: pay.amountRs,
          expiresAt, via: 'Safepay (automatic)',
        });
      } catch (e) { console.error('[safepay] notify failed:', e.message); }
    }
    return payments.findOne({ _id: pay._id });
  }

  const page = (title, msg) => (req, res) =>
    res.send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — ReamBook</title></head>` +
      `<body style="font-family:sans-serif;text-align:center;padding:48px 16px"><h2>${title}</h2><p>${msg}</p><p>App mein wapas jayein.</p></body></html>`);

  app.get('/api/safepay/config', deps.auth, (req, res) => {
    res.json({ configured: cfg.configured, mode: cfg.mode, plans: deps.publicPlans() });
  });

  app.post('/api/safepay/checkout', deps.auth, async (req, res) => {
    try {
      if (!cfg.configured) return res.status(503).json({ error: 'payments not configured' });
      const { plan } = req.body || {};
      const p = plans[plan];
      if (!p) return res.status(400).json({ error: 'unknown plan' });
      const { ObjectId } = require('mongodb');
      const u = await deps.getUsers().findOne({ _id: new ObjectId(req.userId) }, { projection: { email: 1 } });
      const userEmail = u ? u.email : '';
      const tracker = await client.createSession({
        planDef: p,
        metadata: { userEmail, plan, userId: String(req.userId) },
      });
      await deps.getPayments().insertOne({
        kind: 'safepay', tracker, txnRefNo: tracker,
        userId: new ObjectId(req.userId), plan, amountRs: p.amountRs,
        status: 'pending', createdAt: new Date(),
      });
      const tbt = await client.createPassportToken();
      const checkoutUrl = buildCheckoutUrl(cfg, {
        tracker, tbt, source: 'hosted',
        redirectUrl: deps.serverUrl + '/pay/safepay/done?tracker=' + encodeURIComponent(tracker),
        cancelUrl: deps.serverUrl + '/pay/safepay/cancel',
      });
      console.log('[safepay] checkout created', tracker, plan);
      res.json({ checkoutUrl, tracker, amountRs: p.amountRs });
    } catch (e) {
      console.error('[safepay] checkout failed:', e.message);
      res.status(500).json({ error: 'could not start payment', detail: String((e && e.message) || '').slice(0, 300) });
    }
  });

  // The app polls this after returning from the hosted checkout.
  app.get('/api/safepay/status', deps.auth, async (req, res) => {
    try {
      const tracker = String(req.query.tracker || '');
      const { ObjectId } = require('mongodb');
      let pay = await deps.getPayments().findOne({ tracker, userId: new ObjectId(req.userId) });
      if (!pay) return res.status(404).json({ error: 'payment not found' });
      if (pay.status !== 'success' && cfg.configured) pay = (await settle(tracker)) || pay;
      const u = await deps.getUsers().findOne({ _id: new ObjectId(req.userId) }, { projection: { plan: 1, planExpiresAt: 1 } });
      res.json({ status: pay.status, plan: u ? (u.plan || 'free') : 'free', planExpiresAt: u ? (u.planExpiresAt || null) : null });
    } catch (e) {
      console.error('[safepay] status failed:', e.message);
      res.status(500).json({ error: 'status check failed' });
    }
  });

  // Webhook: verify -> ack 200 immediately -> settle in the background.
  app.post('/api/safepay/webhook', async (req, res) => {
    const sig = req.headers['x-sfpy-signature'];
    if (!cfg.webhookSecret || !verifyWebhookSignature(req.body, sig, cfg.webhookSecret)) {
      console.error('[safepay] webhook signature check failed');
      return res.status(400).json({ error: 'invalid signature' });
    }
    const event = req.body || {};
    const tracker = extractTracker(event);
    res.status(200).json({ ok: true });
    if (event.type === 'payment.succeeded' && tracker) {
      settle(tracker).catch((e) => console.error('[safepay] webhook settle failed:', e.message));
    } else {
      console.log('[safepay] webhook', event.type || '(no type)', tracker || '(no tracker)');
    }
  });

  app.get('/pay/safepay/done', async (req, res) => {
    const tracker = String(req.query.tracker || '');
    if (tracker && cfg.configured) { try { await settle(tracker); } catch (e) { /* status poll will retry */ } }
    page('Payment complete! 🎉', 'Agar payment kamyab hui hai to Premium kuch seconds mein active ho jayega.')(req, res);
  });
  app.get('/pay/safepay/cancel', page('Payment cancel ho gayi', 'Koi paisa nahi kata. Aap jab chahein dobara koshish kar sakte hain.'));

  return { settle, cfg };
}

module.exports = {
  HOSTS, getConfig, planToPaisa, buildCheckoutUrl,
  verifyWebhookSignature, extractTracker, createClient, registerSafepay,
};
