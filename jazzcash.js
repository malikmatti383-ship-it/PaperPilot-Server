'use strict';
/**
 * JazzCash Page Redirection v2.0 helper (one-time payments).
 *
 * Flow:
 *   1. App calls POST /api/pay/create  -> server returns { postUrl, fields, txnRefNo }
 *   2. App auto-submits the fields as a form to postUrl (JazzCash hosted page, in WebView)
 *   3. User pays with JazzCash wallet (MPIN) or card
 *   4. JazzCash POSTs the result to our ReturnURL -> server verifies pp_SecureHash,
 *      marks the payment, and activates the premium plan
 *   5. App polls GET /api/pay/status?txnRefNo=... until status = success
 *
 * Docs: JazzCash "API Docs" (Page Redirection v2.0) + IPN Implementation Guide.
 * Amount is in paisa (Rs * 100). Hash = HMAC-SHA256 over all pp_* fields
 * (alphabetical by field name, empty values skipped, joined with '&',
 *  integrity salt prepended with '&'), keyed with the integrity salt.
 */
const crypto = require('crypto');

const SANDBOX_POST_URL = 'https://sandbox.jazzcash.com.pk/CustomerPortal/transactionmanagement/merchantform/';
const PROD_POST_URL = 'https://payments.jazzcash.com.pk/CustomerPortal/transactionmanagement/merchantform';

// Owner's pricing (2026-10-20): base rate Rs 300/month.
// 6 months: 300*6 = 1800, 13% discount -> Rs 1566.
// 1 year:   300*12 = 3600, 26% discount -> Rs 2664.
const PLANS = {
  monthly:    { amountRs: 300,  days: 30,  label: 'PaperPilotPremium-1Month' },
  halfyearly: { amountRs: 1566, days: 180, label: 'PaperPilotPremium-6Months' },
  yearly:     { amountRs: 2664, days: 365, label: 'PaperPilotPremium-1Year' },
};

/** YYYYMMDDHHMMSS in Asia/Karachi (UTC+5, no DST). */
function txnDateTime(d = new Date(), plusDays = 0) {
  const k = new Date(d.getTime() + (5 * 3600 + plusDays * 86400) * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return (
    k.getUTCFullYear() + p(k.getUTCMonth() + 1) + p(k.getUTCDate()) +
    p(k.getUTCHours()) + p(k.getUTCMinutes()) + p(k.getUTCSeconds())
  );
}

/** Unique, max-20-char alphanumeric reference, e.g. PP2610171030451234 */
function makeTxnRefNo() {
  return 'PP' + txnDateTime().slice(2) + Math.floor(1000 + Math.random() * 9000);
}

/**
 * Generic secure-hash: sort pp_* keys alphabetically, skip pp_SecureHash itself
 * and empty values, join values with '&', prepend salt + '&', HMAC-SHA256 with salt.
 */
function secureHash(fields, salt) {
  const keys = Object.keys(fields)
    .filter((k) => k !== 'pp_SecureHash' && /^pp/i.test(k))
    .sort();
  let s = salt;
  for (const k of keys) {
    const v = fields[k];
    if (v === undefined || v === null || v === '' || v === 'undefined') continue;
    s += '&' + String(v);
  }
  return crypto.createHmac('sha256', salt).update(s, 'utf8').digest('hex').toUpperCase();
}

/** Fields to POST to JazzCash. cfg = { merchantId, password, integritySalt, returnUrl } */
function buildPaymentFields(cfg, { amountRs, billRef, description, txnRefNo, userId }) {
  const fields = {
    pp_Version: '2.0',
    pp_TxnType: '',
    pp_Language: 'EN',
    pp_MerchantID: cfg.merchantId,
    pp_SubMerchantID: '',
    pp_Password: cfg.password,
    pp_BankID: '',
    pp_ProductID: '',
    pp_TxnRefNo: txnRefNo,
    pp_Amount: String(Math.round(amountRs * 100)), // paisa
    pp_TxnCurrency: 'PKR',
    pp_TxnDateTime: txnDateTime(),
    pp_TxnExpiryDateTime: txnDateTime(new Date(), 1),
    pp_BillReference: String(billRef).replace(/[^a-zA-Z0-9]/g, '').slice(0, 20) || txnRefNo,
    pp_Description: String(description).replace(/[^a-zA-Z0-9 ]/g, '').slice(0, 60),
    pp_IsRegisteredCustomer: 'No',
    pp_ReturnURL: cfg.returnUrl,
    ppmpf_1: String(userId || ''),
    ppmpf_2: '',
    ppmpf_3: '',
    ppmpf_4: '',
    ppmpf_5: '',
  };
  fields.pp_SecureHash = secureHash(fields, cfg.integritySalt);
  return fields;
}

/** Verify the hash on JazzCash's return/IPN POST. Returns true/false. */
function verifyReturnHash(body, salt) {
  const got = String(body.pp_SecureHash || '').toUpperCase();
  if (!got || !salt) return false;
  return secureHash(body, salt) === got;
}

module.exports = {
  SANDBOX_POST_URL,
  PROD_POST_URL,
  PLANS,
  txnDateTime,
  makeTxnRefNo,
  secureHash,
  buildPaymentFields,
  verifyReturnHash,
};
