/**
 * PaperPilot — mail sending (owner notifications + login codes).
 *
 * PRIMARY route: Brevo (https://api.brevo.com) over HTTPS, because Render
 * blocks outbound SMTP connections entirely (ports 465 AND 587 timed out at
 * connect time, verified 2026-10-21). Config (Render env vars — secrets ONLY
 * there, never in code or chat):
 *   BREVO_API_KEY        Brevo API key (xkeysib-...)
 *   GMAIL_USER           sender Gmail address (must be a verified Brevo sender)
 *   OWNER_NOTIFY_EMAIL   owner-notification recipient
 *
 * FALLBACK route (local dev only): Gmail SMTP via App Password
 * (GMAIL_USER + GMAIL_APP_PASSWORD).
 *
 * If mail is not configured, owner notifications are skipped with a log
 * line — payments and activations NEVER fail because email failed. Login
 * codes instead THROW, so a code is never stored that the user did not get.
 */
'use strict';

let transporter = null;
let warned = false;

function mailConfig() {
  return {
    to: process.env.OWNER_NOTIFY_EMAIL || '',
    user: process.env.GMAIL_USER || '',
    pass: process.env.GMAIL_APP_PASSWORD || '',
  };
}

function mailConfigured() {
  const c = mailConfig();
  if (brevoKey()) return Boolean(c.to && senderEmail());
  return Boolean(c.to && c.user && c.pass);
}

function clean(v) { return String(v || '').trim(); }

function brevoKey() { return clean(process.env.BREVO_API_KEY); }

function senderEmail() {
  return clean(process.env.GMAIL_USER) || clean(process.env.BREVO_SENDER);
}

// Brevo transactional email API — plain HTTPS, works from any host.
async function sendViaBrevo({ to, subject, text }) {
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': brevoKey(),
      'content-type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify({
      sender: { name: 'ReamBook', email: senderEmail() },
      to: [{ email: to }],
      subject,
      textContent: text,
    }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error('Brevo send failed (' + res.status + '): ' + body.slice(0, 200));
  }
}

// One delivery path for every mail this module sends.
async function deliver({ to, subject, text }) {
  if (brevoKey()) {
    await sendViaBrevo({ to, subject, text });
    return;
  }
  const c = mailConfig();
  await getTransporter().sendMail({ from: `ReamBook <${c.user}>`, to, subject, text });
}

function getTransporter() {
  if (transporter) return transporter;
  // Required lazily so the server still runs if the package is absent.
  const nodemailer = require('nodemailer');
  const c = mailConfig();
  // Explicit host/port instead of service:'gmail': port 587 (STARTTLS) and
  // forced IPv4 — the 'gmail' preset (port 465) timed out connecting from
  // Render (observed 2026-10-21: send hung the full 2-minute default
  // connectionTimeout). Short timeouts keep failures fast and visible.
  transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    family: 4,
    connectionTimeout: 30000,
    greetingTimeout: 15000,
    socketTimeout: 30000,
    auth: { user: c.user, pass: c.pass },
  });
  return transporter;
}

/** Sender-side check only (used by login codes): Brevo key, or Gmail user + app password. */
function mailSenderConfigured() {
  if (brevoKey()) return Boolean(senderEmail());
  const c = mailConfig();
  return Boolean(c.user && c.pass);
}

/**
 * Sends a 6-digit login code to a customer. THROWS on failure (not configured
 * or SMTP error) so the caller never stores a code the user did not receive.
 */
async function sendLoginCode(toEmail, code) {
  if (!mailSenderConfigured()) {
    const e = new Error('mail not configured');
    e.code = 'MAIL_NOT_CONFIGURED';
    throw e;
  }
  await deliver({
    to: toEmail,
    subject: `ReamBook login code: ${code}`,
    text: [
      `Your ReamBook login code is: ${code}`,
      '',
      'Enter this code in the ReamBook app to log in.',
      'The code expires in 10 minutes.',
      '',
      'If you did not request this code, you can safely ignore this email.',
    ].join('\n'),
  });
  return true;
}

/** Best-effort: resolves true if sent, false if skipped/failed. Never throws. */
async function notifyOwner(subject, text) {
  try {
    if (!mailConfigured()) {
      if (!warned) {
        console.warn('[mail] owner notifications not configured — skipping emails.');
        warned = true;
      }
      return false;
    }
    const c = mailConfig();
    await deliver({ to: c.to, subject, text });
    console.log('[mail] owner notified:', subject);
    return true;
  } catch (e) {
    console.error('[mail] notify failed (ignored):', e.message);
    return false;
  }
}

function fmtDate(d) {
  try { return new Date(d).toISOString().slice(0, 10); } catch (e) { return String(d || ''); }
}

/** A user submitted a manual payment (JazzCash/Easypaisa transfer + txn ID). */
function notifyManualRequest({ userEmail, userName, plan, amountRs, method, txnRefNo, senderName, senderNumber, adminUrl }) {
  const lines = [
    'A customer has sent a manual payment and is waiting for activation.',
    '',
    `Customer Gmail : ${userEmail || ''}${userName ? ` (${userName})` : ''}`,
    `Plan           : ${plan} — Rs ${amountRs}`,
    `Paid via       : ${method}`,
    `Transaction ID : ${txnRefNo}`,
  ];
  if (senderName) lines.push(`Sender name    : ${senderName}`);
  if (senderNumber) lines.push(`Sender number  : ${senderNumber}`);
  lines.push(
    '',
    'Next step: check this Transaction ID in your payment app (JazzCash / Easypaisa / NayaPay / SadaPay / bank).',
    'If the money has arrived, open the admin page and tap Approve:',
    adminUrl || '(set SERVER_URL to get the admin link here)',
  );
  return notifyOwner(`ReamBook: New payment — ${userEmail} — ${plan} (Rs ${amountRs})`, lines.join('\n'));
}

/** A subscription became active (manual approval OR JazzCash auto payment). */
function notifyActivated({ userEmail, plan, amountRs, expiresAt, via }) {
  const lines = [
    'A ReamBook subscription is now ACTIVE.',
    '',
    `Customer Gmail : ${userEmail || ''}`,
    `Plan           : ${plan}${amountRs ? ` — Rs ${amountRs}` : ''}`,
    `Active until   : ${fmtDate(expiresAt)}`,
    `Activated via  : ${via}`,
  ];
  return notifyOwner(`ReamBook: Subscription active — ${userEmail} — ${plan}`, lines.join('\n'));
}

/** Sends a 6-digit admin-key reset code to the owner. THROWS on failure. */
async function sendAdminResetCode(toEmail, code) {
  if (!mailSenderConfigured()) {
    const e = new Error('mail not configured');
    e.code = 'MAIL_NOT_CONFIGURED';
    throw e;
  }
  await deliver({
    to: toEmail,
    subject: `ReamBook admin key reset code: ${code}`,
    text: [
      `Your ReamBook admin key reset code is: ${code}`,
      '',
      'Enter this code on the admin page (/admin) together with your new admin key.',
      'The code expires in 10 minutes and can be used only once.',
      '',
      'If you did not request this code, someone may be trying to reset your admin key — you can safely ignore this email (nothing changes without the code).',
    ].join('\n'),
  });
  return true;
}

module.exports = { notifyOwner, notifyManualRequest, notifyActivated, mailConfigured, mailSenderConfigured, sendLoginCode, sendAdminResetCode };
