/**
 * PaperPilot — owner email notifications (best effort).
 *
 * Sends mail via the owner's Gmail using an App Password (Gmail SMTP).
 * Config (Render env vars — secrets ONLY there, never in code or chat):
 *   OWNER_NOTIFY_EMAIL   recipient, e.g. the owner's Gmail
 *   GMAIL_USER           sender Gmail address
 *   GMAIL_APP_PASSWORD   16-char Gmail App Password for GMAIL_USER
 *
 * If any of these are missing, notifications are skipped with a log line —
 * payments and activations NEVER fail because email failed.
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
  return Boolean(c.to && c.user && c.pass);
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

/** Sender-side check only (used by login codes): needs GMAIL_USER + APP PASSWORD. */
function mailSenderConfigured() {
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
  const c = mailConfig();
  await getTransporter().sendMail({
    from: `PaperPilot <${c.user}>`,
    to: toEmail,
    subject: `PaperPilot login code: ${code}`,
    text: [
      `Your PaperPilot login code is: ${code}`,
      '',
      'Enter this code in the PaperPilot app to log in.',
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
    await getTransporter().sendMail({
      from: `PaperPilot <${c.user}>`,
      to: c.to,
      subject,
      text,
    });
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
  return notifyOwner(`PaperPilot: New payment — ${userEmail} — ${plan} (Rs ${amountRs})`, lines.join('\n'));
}

/** A subscription became active (manual approval OR JazzCash auto payment). */
function notifyActivated({ userEmail, plan, amountRs, expiresAt, via }) {
  const lines = [
    'A PaperPilot subscription is now ACTIVE.',
    '',
    `Customer Gmail : ${userEmail || ''}`,
    `Plan           : ${plan}${amountRs ? ` — Rs ${amountRs}` : ''}`,
    `Active until   : ${fmtDate(expiresAt)}`,
    `Activated via  : ${via}`,
  ];
  return notifyOwner(`PaperPilot: Subscription active — ${userEmail} — ${plan}`, lines.join('\n'));
}

module.exports = { notifyOwner, notifyManualRequest, notifyActivated, mailConfigured, mailSenderConfigured, sendLoginCode };
