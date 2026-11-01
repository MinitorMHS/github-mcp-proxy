// HTML pages served by the OAuth handler: the optional consent page (REQUIRE_CONSENT=true)
// and the error page. Kept apart from index.js so the page markup can be edited on its own.
// No scripts, no external resources; works the same in every browser.

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;',
    '"': '&quot;', "'": '&#39;',
  }[c]));
}

function htmlPage(title, body, status = 200, baseHeaders) {
  const headers = new Headers(baseHeaders);
  headers.set('Content-Type', 'text/html; charset=utf-8');
  headers.set(
    'Content-Security-Policy',
    // No form-action directive on purpose: Chromium also applies it to the redirect that
    // follows a form POST, which blocks the redirect to github.com / the client.
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"
  );
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Cache-Control', 'no-store');
  const doc = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${escapeHtml(title)}</title>
<style>
  body{font:16px/1.5 system-ui,sans-serif;max-width:30rem;margin:3rem auto;padding:0 1rem}
  h1{font-size:1.3rem}
  .box{border:1px solid color-mix(in srgb,currentColor 25%,transparent);border-radius:.6rem;padding:1rem;margin:1rem 0}
  .warn{border-color:#c0392b;color:#c0392b}
  label{display:block;margin:.5rem 0;cursor:pointer}
  code{background:color-mix(in srgb,currentColor 12%,transparent);padding:.1rem .3rem;border-radius:.25rem;word-break:break-all}
  .row{display:flex;flex-direction:row-reverse;gap:.75rem;margin-top:1.25rem}
  button{flex:1;font:inherit;padding:.65rem;border-radius:.5rem;border:1px solid currentColor;cursor:pointer;background:transparent;color:inherit}
  button.primary{background:#1f6feb;border-color:#1f6feb;color:#fff}
</style></head><body>${body}</body></html>`;
  return new Response(doc, { status, headers });
}

export function errorPage(status, message) {
  return htmlPage('Authorization error', `<h1>Authorization error</h1><p>${escapeHtml(message)}</p>`, status);
}

export function consentPage(desc, consent, defaultWrite, readOnly) {
  const loopback = desc.redirectIsLoopback
    ? `<div class="box warn"><strong>Local app.</strong> The tokens go to a program on this device. Any local process could be listening, whatever name it claims.</div>`
    : '';
  const verified = desc.clientDomain
    ? `<p>Verified domain: <code>${escapeHtml(desc.clientDomain)}</code></p>`
    : `<p><small>The name above is self-reported by the client and not verified.</small></p>`;
  const access = readOnly
    ? `<div class="box"><strong>Access level:</strong> read-only (this server is set to READ_ONLY)</div>`
    : `<div class="box">
    <strong>Access level</strong>
    <label><input type="radio" name="access" value="read"${defaultWrite ? '' : ' checked'}> Read-only: browse repos, issues, pull requests</label>
    <label><input type="radio" name="access" value="write"${defaultWrite ? ' checked' : ''}> Read &amp; write: also create, edit and merge</label>
  </div>`;
  const body = `<h1>Connect to GitHub</h1>
<div class="box">
  <p><strong>${escapeHtml(desc.clientName)}</strong> wants to use your GitHub account through this proxy.</p>
  ${verified}
  <p>After you approve, access tokens are sent to:<br><code>${escapeHtml(desc.redirectHost)}</code></p>
</div>
${loopback}
<form method="post" action="/authorize">
  <input type="hidden" name="handle" value="${escapeHtml(consent.handle)}">
  ${access}
  <p><small>You will sign in to GitHub next. Only approve clients you set up yourself.</small></p>
  <!-- Approve comes first in the DOM: pressing Enter on a radio button submits the FIRST
       submit button, which must never be Deny. row-reverse keeps Deny on the left. -->
  <div class="row">
    <button type="submit" name="action" value="approve" class="primary">Approve</button>
    <button type="submit" name="action" value="deny">Deny</button>
  </div>
</form>`;
  return htmlPage('Connect to GitHub', body, 200, consent.headers);
}
