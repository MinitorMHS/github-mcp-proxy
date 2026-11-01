import {
  OAuthProvider,
  AuthorizationError,
  OAuthError,
  authorizationErrorRedirect,
  getOAuthApi,
} from '@cloudflare/workers-oauth-provider';

// ============================================================
// 0. Configuration
// ============================================================

// Public origin this Worker is served from. Must match the custom domain you
// attach to the Worker and the callback URL on your GitHub OAuth App.
const PUBLIC_ORIGIN = 'https://github.miix.ir';
const MCP_PATH = '/mcp';

const TARGET_HOST = 'api.githubcopilot.com';
const GITHUB_UA = 'github-mcp-proxy';

// Scopes this proxy hands to MCP clients.
//   mcp:read       - required for every connection
//   mcp:write      - without it the proxy forces GitHub's read-only mode
//   offline_access - lets clients keep a refresh token
const SCOPES_SUPPORTED = ['mcp:read', 'mcp:write', 'offline_access'];

// Same default set GitHub documents for its own MCP server. Override with the
// GITHUB_SCOPES var (space separated) to add e.g. `workflow`.
const DEFAULT_GITHUB_SCOPES =
  'repo read:org read:user user:email read:packages write:packages read:project project gist notifications';

const ACCESS_TOKEN_TTL = 3600; // seconds, proxy-issued access tokens
const DCR_CLIENT_TTL = 60 * 60 * 24 * 90; // seconds, dynamically registered clients
// Refresh the upstream GitHub token when less than this remains (GitHub App
// user tokens expire after 8h; OAuth App tokens never expire).
const UPSTREAM_REFRESH_WINDOW_MS = (ACCESS_TOKEN_TTL + 900) * 1000;
const PURGE_CURSOR_KEY = 'purge:cursor';

// ============================================================
// 1. Encryption helpers (AES-256-GCM)
// ============================================================
async function importKey(keyB64) {
  const raw = Uint8Array.from(atob(keyB64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

async function encryptToken(plaintext, keyB64) {
  const key = await importKey(keyB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext)
  );
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decryptToken(encoded, keyB64) {
  const key = await importKey(keyB64);
  const combined = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  return new TextDecoder().decode(plaintext);
}

// ============================================================
// 2. GitHub helpers
// ============================================================
function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// PKCE (S256) for the proxy -> GitHub leg.
async function pkcePair() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return { verifier, challenge: b64url(new Uint8Array(digest)) };
}

function githubTokenRequest(env, params) {
  return fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'User-Agent': GITHUB_UA,
    },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      ...params,
    }),
  });
}

function githubUserRequest(token) {
  return fetch('https://api.github.com/user', {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': GITHUB_UA,
    },
  });
}

// Turns GitHub's token response into the props we persist (tokens encrypted).
async function buildProps(env, tokenData, login) {
  const props = {
    encryptedGithubToken: await encryptToken(tokenData.access_token, env.ENCRYPTION_KEY),
    login,
  };
  // Present only for GitHub Apps with expiring user tokens.
  if (tokenData.refresh_token) {
    props.encryptedRefreshToken = await encryptToken(tokenData.refresh_token, env.ENCRYPTION_KEY);
  }
  if (tokenData.expires_in) {
    props.upstreamExpiresAt = Date.now() + Number(tokenData.expires_in) * 1000;
  }
  return props;
}

// Refreshes an expiring GitHub token during a proxy refresh-token exchange.
async function refreshUpstream(env, props, grantId, userId) {
  const transient = (description) =>
    new OAuthError('temporarily_unavailable', {
      description,
      statusCode: 503,
      headers: { 'Retry-After': '30' },
    });

  let refreshToken;
  try {
    refreshToken = await decryptToken(props.encryptedRefreshToken, env.ENCRYPTION_KEY);
  } catch (err) {
    console.error('Refresh token decryption failed', err.message);
    throw new OAuthError('server_error', { description: 'Stored credentials unreadable', statusCode: 500 });
  }

  let resp;
  try {
    resp = await githubTokenRequest(env, { grant_type: 'refresh_token', refresh_token: refreshToken });
  } catch {
    throw transient('GitHub is unreachable; retry shortly');
  }
  if (resp.status >= 500) throw transient('GitHub is unavailable; retry shortly');

  const data = await resp.json().catch(() => ({}));
  if (!data.access_token) {
    // GitHub answers HTTP 200 with an `error` field.
    if (data.error === 'bad_refresh_token' || data.error === 'invalid_grant') {
      await getOAuthApi(providerOptions, env).revokeGrant(grantId, userId);
      throw new OAuthError('invalid_grant', {
        description: 'GitHub authorization expired; reconnect to authorize again',
      });
    }
    console.error('Upstream refresh failed:', data.error || resp.status);
    throw new OAuthError('server_error', { description: 'Upstream token refresh failed', statusCode: 502 });
  }

  const fresh = await buildProps(env, data, props.login);
  return { ...props, ...fresh };
}

// ============================================================
// 3. Token exchange callback (runs on code + refresh exchanges)
// ============================================================
async function tokenExchangeCallback(opts) {
  const { env, grantType, grantId, userId, requestedScope } = opts;

  // grantId/userId let the API handler revoke the grant if GitHub rejects the token.
  let props = { ...opts.props, grantId, userId };

  if (
    grantType === 'refresh_token' &&
    props.encryptedRefreshToken &&
    props.upstreamExpiresAt &&
    props.upstreamExpiresAt - Date.now() < UPSTREAM_REFRESH_WINDOW_MS
  ) {
    props = await refreshUpstream(env, props, grantId, userId);
  }

  const result = {
    newProps: props, // persisted on the grant (carries rotated upstream tokens)
    // Per-token flag derived from the scopes this token actually carries.
    accessTokenProps: { ...props, canWrite: requestedScope.includes('mcp:write') },
  };

  if (props.upstreamExpiresAt) {
    const remaining = Math.floor((props.upstreamExpiresAt - Date.now()) / 1000) - 60;
    result.accessTokenTTL = Math.max(60, Math.min(ACCESS_TOKEN_TTL, remaining));
  }
  return result;
}

// ============================================================
// 4. API handler (resource server): proxies to GitHub MCP
// ============================================================
const RESOURCE_METADATA_URL = `${PUBLIC_ORIGIN}/.well-known/oauth-protected-resource${MCP_PATH}`;

const mcpApiHandler = {
  async fetch(request, env, ctx) {
    const props = ctx.props || {};
    if (!props.encryptedGithubToken) {
      return new Response('Missing upstream token', { status: 401 });
    }

    // Rate limit per authenticated user (falls back to IP for legacy grants).
    // IP keys would lump together every client behind a shared egress address.
    if (env.MCP_RL) {
      const key = props.userId || request.headers.get('CF-Connecting-IP') || 'unknown';
      const { success } = await env.MCP_RL.limit({ key });
      if (!success) return new Response('Rate limited', { status: 429, headers: { 'Retry-After': '60' } });
    }

    let upstreamToken;
    try {
      upstreamToken = await decryptToken(props.encryptedGithubToken, env.ENCRYPTION_KEY);
    } catch (err) {
      console.error('Token decryption failed', err.message);
      return new Response('Token decryption failed', { status: 500 });
    }

    const url = new URL(request.url);
    const targetUrl = new URL(`https://${TARGET_HOST}${url.pathname}${url.search}`);

    const headers = new Headers(request.headers);
    headers.set('Authorization', `Bearer ${upstreamToken}`);
    for (const h of [
      'Cookie', 'CF-Connecting-IP', 'X-Forwarded-For', 'CF-Connecting-Port',
      'CF-EW-Via', 'CF-Ray', 'X-Forwarded-Proto', 'X-Real-IP',
    ]) {
      headers.delete(h);
    }

    // Without mcp:write (READ_ONLY=true) GitHub's server only exposes read tools.
    // Tokens issued before this logic existed have no canWrite flag, so they stay
    // read-only until their next refresh.
    if (props.canWrite !== true) headers.set('X-MCP-Readonly', 'true');
    if (env.MCP_LOCKDOWN === 'true') headers.set('X-MCP-Lockdown', 'true');

    const upstream = await fetch(
      new Request(targetUrl, {
        method: request.method,
        headers,
        body: request.body,
        redirect: 'manual',
      })
    );

    // GitHub rejected the stored token. Only treat it as dead if the REST API agrees,
    // then revoke the grant so the client is forced through a fresh authorization
    // instead of refreshing proxy tokens forever.
    if (upstream.status === 401) {
      let dead = false;
      try {
        dead = (await githubUserRequest(upstreamToken)).status === 401;
      } catch {
        // network error: leave the grant alone
      }
      if (dead && props.grantId && props.userId) {
        try {
          await env.OAUTH_PROVIDER.revokeGrant(props.grantId, props.userId);
        } catch (err) {
          console.error('revokeGrant failed', err.message);
        }
      }
      return new Response('GitHub rejected the stored token. Reconnect to authorize again.', {
        status: 401,
        headers: {
          'WWW-Authenticate': `Bearer error="invalid_token", error_description="GitHub token rejected", resource_metadata="${RESOURCE_METADATA_URL}"`,
        },
      });
    }

    const responseHeaders = new Headers(upstream.headers);
    if (upstream.status === 403) {
      // GitHub's remote server answers missing OAuth scopes with a challenge that
      // points the client at GitHub. Clients can't step up through this proxy, so
      // drop the challenge and log what is missing (add it via GITHUB_SCOPES).
      const challenge = responseHeaders.get('WWW-Authenticate');
      if (challenge && /insufficient_scope/i.test(challenge)) {
        console.warn('GitHub scope challenge:', challenge);
        responseHeaders.delete('WWW-Authenticate');
      }
    }

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    });
  },
};

// ============================================================
// 5. OAuth handler (authorize -> GitHub -> callback)
// ============================================================
const oauthHandler = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const helpers = env.OAUTH_PROVIDER;

    // ---- GET /authorize: straight through to GitHub (no consent page) ----
    if (request.method === 'GET' && url.pathname === '/authorize') {
      let authRequest;
      try {
        authRequest = await helpers.parseAuthRequest(request);
      } catch (error) {
        if (error instanceof AuthorizationError) {
          if (error.redirectUri) {
            const redirect = new URL(error.redirectUri);
            redirect.searchParams.set('error', error.code);
            redirect.searchParams.set('error_description', error.description);
            if (error.state) redirect.searchParams.set('state', error.state);
            if (error.issuer) redirect.searchParams.set('iss', error.issuer);
            return Response.redirect(redirect.toString(), 302);
          }
          return errorPage(400, error.description || 'Unknown error');
        }
        throw error;
      }

      if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET || !env.ENCRYPTION_KEY) {
        console.error('Missing GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET or ENCRYPTION_KEY');
        return errorPage(500, 'This server is not configured yet.');
      }

      // Without a consent page, the redirect allowlist is what stops someone else's
      // dynamically registered client from collecting tokens for your GitHub account.
      console.log('authorize: client', authRequest.clientId, 'redirect_uri', authRequest.redirectUri);
      if (!redirectAllowed(authRequest.redirectUri, env.ALLOWED_REDIRECT_URIS)) {
        console.warn('Rejected redirect_uri not on ALLOWED_REDIRECT_URIS:', authRequest.redirectUri);
        return errorPage(400, 'This client\'s redirect address is not allowed on this server.');
      }

      if (env.REQUIRE_CONSENT === 'true') {
        const description = await helpers.describeConsent(authRequest);
        const consent = await helpers.beginConsent(authRequest);
        return consentPage(description, consent, env.READ_ONLY !== 'true', env.READ_ONLY === 'true');
      }

      // No consent page: write access unless READ_ONLY=true.
      const scope = approvedScopes(authRequest.scope, env.READ_ONLY !== 'true');
      return beginGithubLogin(helpers, env, url, authRequest, scope);
    }

    // ---- POST /authorize: consent decision (only when REQUIRE_CONSENT=true) ----
    if (request.method === 'POST' && url.pathname === '/authorize' && env.REQUIRE_CONSENT === 'true') {
      let form;
      try {
        form = await request.formData();
      } catch {
        return errorPage(400, 'Invalid form submission.');
      }
      const handle = form.get('handle');
      if (typeof handle !== 'string' || !handle) return errorPage(400, 'Missing consent handle.');

      try {
        if (form.get('action') !== 'approve') {
          const denied = await helpers.denyConsent(request, handle);
          return new Response(null, { status: 302, headers: denied.headers });
        }
        const approved = await helpers.approveConsent(request, handle);
        const write = env.READ_ONLY !== 'true' && form.get('access') === 'write';
        const scope = approvedScopes(approved.request.scope, write);
        return beginGithubLogin(helpers, env, url, approved.request, scope, approved.headers);
      } catch (error) {
        if (error instanceof AuthorizationError) {
          return errorPage(400, 'This authorization request expired or was already used. Start again from your MCP client.');
        }
        throw error;
      }
    }

    // ---- GET /callback: GitHub redirects back here ----
    if (request.method === 'GET' && url.pathname === '/callback') {
      let resumed;
      try {
        resumed = await helpers.finishUpstream(request);
      } catch (error) {
        if (error instanceof AuthorizationError) {
          return errorPage(400, 'Authorization request expired, was already used, or belongs to a different browser. Start again from your MCP client.');
        }
        throw error;
      }
      const { request: authRequest, data, headers } = resumed;
      const fail = (code, description) =>
        redirectWith(headers, authorizationErrorRedirect(authRequest, code, description));

      const ghError = url.searchParams.get('error');
      if (ghError) {
        console.warn('GitHub authorization error:', ghError);
        return fail(ghError === 'access_denied' ? 'access_denied' : 'server_error', 'GitHub authorization was not completed');
      }
      const code = url.searchParams.get('code');
      if (!code) return fail('invalid_request', 'GitHub did not return a code');

      let tokenResp;
      try {
        tokenResp = await githubTokenRequest(env, {
          code,
          redirect_uri: `${url.origin}/callback`,
          code_verifier: data?.codeVerifier,
        });
      } catch {
        return fail('temporarily_unavailable', 'Could not reach GitHub');
      }
      if (!tokenResp.ok) return fail('server_error', `GitHub token exchange failed (HTTP ${tokenResp.status})`);

      const tokenData = await tokenResp.json().catch(() => ({}));
      if (!tokenData.access_token) {
        console.error('GitHub token exchange failed:', tokenData.error);
        return fail('server_error', 'GitHub token exchange failed');
      }
      if (tokenData.scope) console.log('GitHub granted scopes:', tokenData.scope);

      // Identify the real GitHub user: becomes the grant's userId so different
      // accounts never share (or revoke) each other's grants.
      let ghUser;
      try {
        const userResp = await githubUserRequest(tokenData.access_token);
        ghUser = userResp.ok ? await userResp.json() : null;
      } catch {
        ghUser = null;
      }
      if (!ghUser?.id || !ghUser?.login) return fail('server_error', 'Could not read the GitHub profile');

      const allowed = (env.ALLOWED_GITHUB_USERS || '')
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      if (allowed.length > 0 && !allowed.includes(ghUser.login.toLowerCase())) {
        console.warn('Rejected GitHub user not on ALLOWED_GITHUB_USERS:', ghUser.login);
        return fail('access_denied', 'This GitHub account is not allowed to use this server');
      }

      try {
        const props = await buildProps(env, tokenData, ghUser.login);
        const { redirectTo } = await helpers.completeAuthorization({
          request: authRequest,
          userId: String(ghUser.id),
          metadata: { login: ghUser.login },
          scope: authRequest.scope,
          props,
        });
        return redirectWith(headers, redirectTo);
      } catch (err) {
        console.error('completeAuthorization failed', err.message);
        return fail('server_error', 'Authorization could not be completed');
      }
    }

    return new Response('Not found', { status: 404 });
  },
};

// ============================================================
// 6. Cleanup (daily 03:00 UTC)
// ============================================================
// The library already expires DCR clients (clientRegistrationTTL) and gives its
// KV records TTLs; purgeExpiredData() sweeps whatever those leave behind
// (grants of expired clients, orphaned tokens) in resumable batches.
async function cleanupHandler(env) {
  const api = getOAuthApi(providerOptions, env);
  let cursor = (await env.OAUTH_KV.get(PURGE_CURSOR_KEY)) || undefined;
  let grants = 0;
  let tokens = 0;

  for (let i = 0; i < 5; i++) {
    const r = await api.purgeExpiredData({ batchSize: 50, cursor });
    grants += r.grantsPurged;
    tokens += r.tokensPurged;
    cursor = r.done ? undefined : r.cursor;
    if (!cursor) break;
  }

  if (cursor) await env.OAUTH_KV.put(PURGE_CURSOR_KEY, cursor);
  else await env.OAUTH_KV.delete(PURGE_CURSOR_KEY);
  console.log(`KV purge: ${grants} grants, ${tokens} tokens${cursor ? ' (sweep continues next run)' : ''}`);
}

// ============================================================
// 7. OAuthProvider + Worker exports
// ============================================================
const providerOptions = {
  apiRoute: MCP_PATH,
  apiHandler: mcpApiHandler,
  defaultHandler: oauthHandler,

  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
  clientRegistrationEndpoint: '/oauth/register',

  scopesSupported: SCOPES_SUPPORTED,
  resourceMetadata: {
    resource: `${PUBLIC_ORIGIN}${MCP_PATH}`,
    authorization_servers: [PUBLIC_ORIGIN],
  },
  requiredScopes: ['mcp:read'],

  accessTokenTTL: ACCESS_TOKEN_TTL,
  clientRegistrationTTL: DCR_CLIENT_TTL,
  tokenExchangeCallback,

  clientIdMetadataDocumentEnabled: false,
  kv: (env) => env.OAUTH_KV,
};

const provider = new OAuthProvider(providerOptions);

export default {
  async fetch(request, env, ctx) {
    // The library serves /oauth/register itself and never hands it to a custom
    // handler, so the DCR spam limit has to sit in front of it.
    const url = new URL(request.url);
    if (request.method === 'POST' && url.pathname === '/oauth/register' && env.REG_RL) {
      const { success } = await env.REG_RL.limit({
        key: request.headers.get('CF-Connecting-IP') || 'unknown',
      });
      if (!success) return new Response('Rate limited', { status: 429, headers: { 'Retry-After': '60' } });
    }
    return provider.fetch(request, env, ctx);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanupHandler(env));
  },
};

// ============================================================
// 8. Helpers
// ============================================================
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;',
    '"': '&quot;', "'": '&#39;',
  }[c]));
}

// Final scope set: always mcp:read, plus mcp:write when write access is allowed.
function approvedScopes(requested, write) {
  const scopes = new Set(
    requested.filter((s) => SCOPES_SUPPORTED.includes(s) && s !== 'mcp:write')
  );
  scopes.add('mcp:read');
  if (write) scopes.add('mcp:write');
  return [...scopes];
}

// Starts the GitHub leg: PKCE + cookie-bound state, then redirect to GitHub.
async function beginGithubLogin(helpers, env, url, authRequest, scope, baseHeaders) {
  const pkce = await pkcePair();
  const upstream = await helpers.beginUpstream(
    { ...authRequest, scope },
    { data: { codeVerifier: pkce.verifier }, headers: baseHeaders }
  );
  const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
  githubAuthUrl.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
  githubAuthUrl.searchParams.set('redirect_uri', `${url.origin}/callback`);
  githubAuthUrl.searchParams.set('scope', env.GITHUB_SCOPES || DEFAULT_GITHUB_SCOPES);
  githubAuthUrl.searchParams.set('state', upstream.state);
  githubAuthUrl.searchParams.set('code_challenge', pkce.challenge);
  githubAuthUrl.searchParams.set('code_challenge_method', 'S256');
  return redirectWith(upstream.headers, githubAuthUrl.toString());
}

// ALLOWED_REDIRECT_URIS: comma-separated; an entry matches exactly or as a prefix.
// Empty/unset allows any redirect URI.
function redirectAllowed(redirectUri, list) {
  const allowed = (list || '').split(',').map((x) => x.trim()).filter(Boolean);
  return allowed.length === 0 || allowed.some((a) => redirectUri === a || redirectUri.startsWith(a));
}

function redirectWith(baseHeaders, location) {
  const headers = new Headers(baseHeaders);
  headers.set('Location', location);
  return new Response(null, { status: 302, headers });
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
  .row{display:flex;gap:.75rem;margin-top:1.25rem}
  button{flex:1;font:inherit;padding:.65rem;border-radius:.5rem;border:1px solid currentColor;cursor:pointer;background:transparent;color:inherit}
  button.primary{background:#1f6feb;border-color:#1f6feb;color:#fff}
</style></head><body>${body}</body></html>`;
  return new Response(doc, { status, headers });
}

function errorPage(status, message) {
  return htmlPage('Authorization error', `<h1>Authorization error</h1><p>${escapeHtml(message)}</p>`, status);
}

function consentPage(desc, consent, defaultWrite, readOnly) {
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
  <div class="row">
    <button type="submit" name="action" value="deny">Deny</button>
    <button type="submit" name="action" value="approve" class="primary">Approve</button>
  </div>
</form>`;
  return htmlPage('Connect to GitHub', body, 200, consent.headers);
}
