/**
 * PaperPilot — frontend auth + cloud sync module (classic script, no modules).
 *
 * Integration (in the PWA's index.html, AFTER app.js):
 *   <script src="https://YOUR-RENDER-URL/static/frontend-auth.js"></script>
 *   OR copy this file into the PWA repo and reference it locally.
 *
 * Flow:
 *   1. On app load call PaperAuth.handleAuthRedirect()  -> captures #token from Google login.
 *   2. If PaperAuth.getToken() is null -> show a "Login with Gmail" button calling PaperAuth.login().
 *   3. After login, call PaperAuth.startAutoSync(getDB, applyRemote):
 *        getDB()        -> return the local DB object (defDB shape)
 *        applyRemote(d) -> merge/replace local DB with cloud data d, then re-render
 *      Sync: pulls cloud data on start; pushes local changes debounced (15s)
 *      and on pagehide / tab-hidden.
 *   4. Logout button -> PaperAuth.logout().then(() => location.reload()).
 */
(function () {
  'use strict';

  // TODO: replace with your Render URL after deploy, e.g. 'https://paper-stock-server.onrender.com'
  var PAPER_SERVER_URL = 'PASTE_RENDER_URL_HERE';

  var TOKEN_KEY = 'ps_token';

  function getToken() {
    try { return localStorage.getItem(TOKEN_KEY); } catch (e) { return null; }
  }
  function setToken(t) {
    try { localStorage.setItem(TOKEN_KEY, t); } catch (e) {}
  }
  function clearToken() {
    try { localStorage.removeItem(TOKEN_KEY); } catch (e) {}
  }

  /** Call once on page load. Captures #token=<...> after Google redirect, saves it, cleans the URL. */
  function handleAuthRedirect() {
    var h = location.hash || '';
    if (h.indexOf('#token=') === 0) {
      var tok = decodeURIComponent(h.slice(7).split('&')[0]);
      if (tok) setToken(tok);
      try { history.replaceState(null, '', location.pathname + location.search); } catch (e) {}
      return tok || null;
    }
    return null;
  }

  /** Start Google login: leaves the app, returns with #token=... */
  function login() {
    location.href = PAPER_SERVER_URL.replace(/\/$/, '') + '/auth/google';
  }

  /** Authed fetch helper. Throws on HTTP error. */
  function api(path, opts) {
    opts = opts || {};
    var headers = opts.headers || {};
    var tok = getToken();
    if (tok) headers['Authorization'] = 'Bearer ' + tok;
    if (opts.body && typeof opts.body === 'object') {
      headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    opts.headers = headers;
    return fetch(PAPER_SERVER_URL.replace(/\/$/, '') + path, opts).then(function (res) {
      if (!res.ok) throw new Error('API ' + res.status);
      return res.json();
    });
  }

  /** Logout: kills the server session and clears the local token. */
  function logout() {
    return api('/api/logout', { method: 'POST' })
      .catch(function () {})
      .then(function () { clearToken(); });
  }

  /**
   * Start cloud sync. v1 = last-write-wins.
   *   getDB()        -> current local DB object
   *   applyRemote(d) -> replace/merge local DB with cloud data d, then re-render UI
   * Returns { pull, push, schedulePush } or null when not logged in.
   */
  function startAutoSync(getDB, applyRemote) {
    if (!getToken()) return null;

    var pushTimer = null;
    var pushing = false;

    function pull() {
      return api('/api/data').then(function (r) {
        if (r && r.data && typeof applyRemote === 'function') applyRemote(r.data, r.updatedAt);
      }).catch(function (e) {
        console.warn('[sync] pull failed:', e.message);
      });
    }

    function pushNow() {
      if (pushing) return Promise.resolve();
      pushing = true;
      var snapshot;
      try { snapshot = getDB(); } catch (e) { pushing = false; return Promise.resolve(); }
      return api('/api/data', { method: 'POST', body: { data: snapshot } })
        .then(function () { pushing = false; })
        .catch(function (e) { pushing = false; console.warn('[sync] push failed:', e.message); });
    }

    function schedulePush() {
      if (pushTimer) clearTimeout(pushTimer);
      pushTimer = setTimeout(pushNow, 15000); // debounce 15s after local changes
    }

    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'hidden') pushNow();
    });
    window.addEventListener('pagehide', function () { pushNow(); });

    pull(); // initial pull on start
    return { pull: pull, push: pushNow, schedulePush: schedulePush };
  }

  window.PaperAuth = {
    getToken: getToken,
    handleAuthRedirect: handleAuthRedirect,
    login: login,
    logout: logout,
    api: api,
    startAutoSync: startAutoSync,
    setServerUrl: function (u) { PAPER_SERVER_URL = u; }
  };
})();
