# PaperPilot Server — Deploy Guide (phone-friendly)

Is server se hoga: Gmail login + har dukandar ka data cloud mein sync (5 devices tak).

## Step 1 — GitHub repo banao (phone se)

1. github.com kholo → **+** → **New repository**
2. Name: `PaperPilot-Server` → **Public** → **Create repository**
3. **Add file** → **Upload files** → is folder ki saari files upload karo:
   `package.json`, `server.js`, `.env.example`, `frontend-auth.js`
   (`.env.example` hi upload karna — kabhi `.env` asli secrets wali upload NA karna)
4. **Commit changes** dabao

## Step 2 — Render par Web Service banao

1. dashboard.render.com kholo → **New +** → **Web Service**
2. **Connect** apna `PaperPilot-Server` repo (pehli baar GitHub connect karna parega)
3. Settings:
   - Name: `paper-stock-server`
   - Region: jo marzi (Singapore qareeb hai)
   - Branch: `main`
   - **Build Command:** `npm install`
   - **Start Command:** `node server.js`
   - Plan: **Free**
4. **Create Web Service** dabao — pehla deploy fail hoga (env vars nahi hain), ghabrana nahi.
5. Deploy ke baad URL milega, misal: `https://paper-stock-server.onrender.com` — isko **note kar lo**.

> NOTE: Free plan par 15 min idle ke baad server "so" jata hai — pehli request 30-50 sec leti hai, uske baad normal. Login/data sync par koi farq nahi parta.

## Step 3 — Env vars lagao (Render → service → Environment)

| Key | Value |
|---|---|
| `MONGODB_URI` | Apne **coco-voice** wali Render service ke Environment se copy karo, aur sirf database ka naam badal do: `...mongodb.net/paperstock?...` (yani `/coco-voice` ya jo bhi ho uski jagah `/paperstock`). Password/username same rehta hai. |
| `GOOGLE_CLIENT_ID` | Step 4 ke baad milega |
| `GOOGLE_CLIENT_SECRET` | Step 4 ke baad milega |
| `SERVER_URL` | Step 2 wala Render URL, misal `https://paper-stock-server.onrender.com` (aakhir mein `/` NAHI) |
| `PWA_URL` | `https://malikmatti383-ship-it.github.io/Paper-Stock` |

Save karne par Render khud dobara deploy karega.

## Step 4 — Google Cloud Console: OAuth client banao

1. console.cloud.google.com kholo → naya project banao (naam: `PaperPilot`)
2. **APIs & Services** → **OAuth consent screen** → **External** → Create:
   - App name: `PaperPilot`, apna email do, baqi chor do → Save
3. **APIs & Services** → **Credentials** → **Create Credentials** → **OAuth client ID**:
   - Application type: **Web application**, naam: `PaperPilot Web`
   - **Authorized redirect URIs** → **Add URI**: `https://paper-stock-server.onrender.com/auth/google/callback`
     (apna asal Render URL lagana — aakhir mein `/auth/google/callback` zaroor ho)
   - **Create** → **Client ID** aur **Client secret** copy karo
4. In dono ko Render ke Environment mein `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` mein paste karo.

> Client secret kabhi chat mein ya repo mein mat bhejo — sirf Render ke env vars mein.

## Step 5 — Verify karo

Browser mein kholo: `https://paper-stock-server.onrender.com/healthz`
`{"ok":true}` nazar aye to server live hai. ✅

Phir kholo: `https://paper-stock-server.onrender.com/auth/google`
Google ka login page aye to OAuth theek hai. ✅

## Uske baad (assistant karega)

- PWA mein `frontend-auth.js` integrate karna (login button + auto-sync)
- Login ke baad token 365 din valid rehta hai — logout sirf user ke khud karne par.
