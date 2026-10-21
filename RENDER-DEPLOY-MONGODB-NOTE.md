# MONGODB_URI trap — read BEFORE guiding Step 3 (env vars) of the Render deploy

Prepared 2026-10-19. Use when the user reaches Step 3 (MONGODB_URI), NOT before.

## The trap
The deploy guide tells him to copy MONGODB_URI from his coco-voice Render service.
That URI is UNTRUSTWORTHY, and PaperPilot has no safety net:

1. PaperPilot server has NO database fallback — missing MONGODB_URI → `required()`
   → `process.exit(1)` (server.js:51/54). Wrong/unreachable URI → `initDb()` catch
   → `process.exit(1)` (server.js:323-325). The process exits BEFORE it listens,
   so the deploy looks dead.
2. CoCo Voice HAS a JSON-file fallback (coco-voice/server.js:147-162) — it keeps
   working with a broken/missing URI. So CoCo looking "live" does NOT prove its
   URI works.
3. Memory confirms CoCo's MongoDB connectivity was NEVER verified (2026-10-08
   setup; the disclosed DB-user password rotation is still pending).

Copying that URI into PaperPilot could copy a broken credential, and the failure
will look like PaperPilot's deploy is broken.

## At Step 3, before he copies anything
Tell him (phone-friendly, one step): Render → coco-voice service → Logs, search
for `[mongo] connected ✅`.
- If present → URI is good. Copy rule: change ONLY the database-name path segment
  to /paperstock (e.g. ...mongodb.net/cocovoice?... → ...mongodb.net/paperstock?...).
  Username, password, host and query string stay byte-identical.
- If the log shows `[mongo] connect failed` or `MONGODB_URI not set — using local
  JSON files` → do NOT copy it. Fix CoCo's URI first (or create a fresh free
  Atlas M0 cluster).

Direct env link (shared in chat 2026-10-08):
https://dashboard.render.com/web/srv-db385te0tbcc73fvijng/env

## If his PaperPilot deploy fails — log lines to look for
Render → paper-stock-server → Logs:
- `[config] Missing required env var: MONGODB_URI` → env var wasn't saved.
- `[db] connect failed: ...` → URI wrong/unreachable. Check Atlas Network Access
  0.0.0.0/0 and that the password has no unencoded special characters.

Also available when his server URL arrives:
~/workspace/your_files/paperpilot_smoke_test.sh (tested, exit 0 on faithful stub) —
its check-1 failure message already points at these exact log lines.

## Rules
- NEVER ask him to paste the URI in chat. He copies it himself from Render.
- Never extract credentials; the 1-minute log check above resolves it.
