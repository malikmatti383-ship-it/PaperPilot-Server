# PaperPilot — Manual Payment Build (2026-10-20)

Ye build ABHI LIVE NAHI hai. Pehle banaya + test kiya gaya hai.
Live tab hoga jab owner permission dein ge (GitHub par update + Render env vars).

## Kya bana hai

### Server (PaperPilot-Server)
- `POST /api/pay/manual` — login user plan choose karke, JazzCash/Easypaisa se
  paisay bhejne ke baad apna Transaction ID app me submit karta hai.
  Methods: JazzCash, Easypaisa, NayaPay, SadaPay aur Bank Transfer —
  jo number owner Render par lagayega, sirf wahi app me nazar ayega.
  Duplicate Transaction ID dobara accept nahi hota (409).
- `GET /api/pay/manual/config` — app ko owner ke payment numbers + plans milte hain.
- `GET /api/pay/manual/mine` — user ko apni requests ki status dikhti hai.
- `GET /admin` — owner ki phone-friendly admin page (admin.html).
  Pending requests ki list: customer Gmail, plan, amount, Transaction ID, sender.
  **Approve** dabane se us customer ka Premium active ho jata hai
  (agar pehle se premium hai to nayi muddat purani expiry ke AAGE se judti hai).
  **Reject** se request reject ho jati hai.
- `GET /api/admin/payments`, `POST /api/admin/payments/:id/activate|reject`
  — ye sab `x-admin-key` (ADMIN_KEY) ke baghair kaam nahi karte.
- Owner email notification (notify.js):
  - Nayi manual request aane par owner ko email: kis Gmail ne, konsa plan,
    kitni raqam, Transaction ID, aur admin page ka link.
  - Subscription active hone par (manual approve YA JazzCash auto payment)
    owner ko email: kis Gmail ki subscription active hui, plan, expiry date.
  - Email configure na ho to server rukta nahi — sirf log me warning ati hai.
- JazzCash gateway wala purana code bilkul nahi chera gaya.

### App (PaperPilot-Web-App) — v175
- Profile sheet me login ke neeche **SUBSCRIPTION** section:
  - Premium active hai to expiry date dikhti hai.
  - Plans (owner ki nayi qeematein, 2026-10-20): Monthly Rs 300 (koi discount nahi) / 6 Months Rs 1,566 (300x6=1800 par 13% discount) / 1 Year Rs 2,664 (300x12=3600 par 26% discount). App me discounted plans par kata hua purana rate aur 'Save %' bhi dikhta hai.
  - Owner ke saare payment numbers jo server par lage hon — JazzCash / Easypaisa / NayaPay / SadaPay / Bank (Copy button ke saath).
  - JazzCash Till aur Mashreq Bank (Raast) ke **QR codes** bhi wahan dikhte hain — user scan karke pay kar sakta hai (dono QR scan-test ho chuke hain; bank QR IBAN se match karta hai).
  - Transaction ID + method + optional naam/number bhar kar **Submit payment**.
  - Apni requests ki status: waiting for verification / verified / not verified.
- sw.js cache v172 -> v175 (taake update sab users ko mile).
- Baqi app (ADD/SALES/STOCK/REPORT/CREDIT, hisaab ke rules) bilkul nahi chera gaya.

## Live karne ke liye Render par ye NAYE env vars lagane honge
- `PAY_JAZZCASH_NUMBER`, `PAY_JAZZCASH_TITLE`
- `PAY_EASYPAISA_NUMBER`, `PAY_EASYPAISA_TITLE`
- `PAY_NAYAPAY_NUMBER`, `PAY_NAYAPAY_TITLE`
- `PAY_SADAPAY_NUMBER`, `PAY_SADAPAY_TITLE`
- `PAY_BANK_NAME`, `PAY_BANK_NUMBER` (account number ya IBAN), `PAY_BANK_TITLE`
- `ADMIN_KEY` — lambi random secret (owner sirf /admin page me dalay ga)
- `OWNER_NOTIFY_EMAIL` — owner ki Gmail (jahan khabar jaye gi)
- `GMAIL_USER`, `GMAIL_APP_PASSWORD` — bhejne wali Gmail + us ka App Password
  (ye dono SIRF Render env me — chat me kabhi nahi)

(Purane env vars — MONGODB_URI, GOOGLE_CLIENT_ID/SECRET, SERVER_URL, PWA_URL —
wali list is se pehle wali hai, woh bhi lazmi hain.)

## Test report (local, 2026-10-20)
Local machine par asal server + asal jaisi (in-memory) MongoDB chala kar
27 checks pass hue (nayi qeematein 300/1566/2664 ki tasdeeq sameet), jin me shamil hain:
server start, plans list, config sirf login ke baad, ghalat/chhota
Transaction ID reject (400), sahi submit, duplicate reject (409),
admin list bina key ke band (401), key ke saath customer Gmail ke saath list,
Approve -> Premium + 30 din expiry, /api/me me premium tasdeeq,
renewal par muddat purani expiry se aage judna, Reject ke baad Activate na hona (409),
/admin page khulna, aur email configure na honay par bhi koi kaam na rukna.
