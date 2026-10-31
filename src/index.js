import { OAuthProvider, AuthorizationError } from '@cloudflare/workers-oauth-provider';

// ============================================================
// 1. API handler (resource server): proxies to GitHub MCP
// ============================================================
const mcpApiHandler = {
  async fetch(request, env, ctx) {
    // The OAuthProvider has already validated the incoming token.
    // ctx.props contains data stored during authorization (e.g., upstream GitHub token).
    const upstreamToken = ctx.props.githubAccessToken;
    if (!upstreamToken) {
      return new Response('Missing upstream token', { status: 401 });
    }

    const TARGET_HOST = 'api.githubcopilot.com';
    const url = new URL(request.url);
    const targetUrl = new URL(`https://${TARGET_HOST}${url.pathname}${url.search}`);

    const proxyRequest = new Request(targetUrl, {
      method: request.method,
      headers: request.headers,
      body: request.body,
      redirect: 'manual',
    });

    proxyRequest.headers.set('Host', TARGET_HOST);
    // Inject the GitHub token obtained during OAuth.
    proxyRequest.headers.set('Authorization', `Bearer ${upstreamToken}`);

    // Strip Cloudflare / client metadata.
    for (const h of [
      'CF-Connecting-IP', 'X-Forwarded-For', 'CF-Connecting-Port',
      'CF-EW-Via', 'CF-Ray', 'X-Forwarded-Proto', 'X-Real-IP',
    ]) {
      proxyRequest.headers.delete(h);
    }

    const response = await fetch(proxyRequest);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  },
};

// ============================================================
// 2. Consent / authorization handler (defaultHandler)
// ============================================================
// Implements the /authorize endpoint with CSRF protection,
// state binding, input sanitization, and a strict CSP.
const consentHandler = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ---- GET /authorize: render consent page ----
    if (request.method === 'GET' && url.pathname === '/authorize') {
      // Parse the OAuth request from the provider.
      const authRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);

      // --- CSRF protection ---
      // Generate a random CSRF token and store it in a secure __Host- cookie.
      const csrfToken = crypto.randomUUID();
      const csrfCookieName = '__Host-csrf';
      const csrfCookie = `${csrfCookieName}=${csrfToken}; Path=/; Secure; HttpOnly; SameSite=Lax`;

      // --- State binding ---
      // Store the OAuth state + CSRF token in KV with a short TTL.
      const stateKey = `state:${authRequest.state}`;
      await env.OAUTH_KV.put(stateKey, JSON.stringify({ csrfToken }), { expirationTtl: 600 });

      // --- Sanitize user-controlled fields before rendering ---
      const clientName = sanitizeHtml(authRequest.clientName || 'Unknown Client');

      const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Authorize ${clientName}</title>
  <style>
    body { font-family: system-ui; max-width: 480px; margin: 4rem auto; }
    .card { border: 1px solid #ddd; padding: 2rem; border-radius: 8px; }
    button { margin-right: 1rem; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Authorize ${clientName}</h2>
    <p>${clientName} is requesting access to your GitHub Copilot MCP data.</p>
    <form method="POST" action="/authorize">
      <input type="hidden" name="state" value="${escapeAttr(authRequest.state)}">
      <input type="hidden" name="csrf" value="${csrfToken}">
      <button type="submit" name="decision" value="allow">Allow</button>
      <button type="submit" name="decision" value="deny">Deny</button>
    </form>
  </div>
</body>
</html>`;

      return new Response(html, {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
          'Set-Cookie': csrfCookie,
        },
      });
    }

    // ---- POST /authorize: handle consent decision ----
    if (request.method === 'POST' && url.pathname === '/authorize') {
      const form = await request.formData();
      const state = form.get('state');
      const csrfFromForm = form.get('csrf');
      const decision = form.get('decision');

      // Validate CSRF against the stored state.
      const stateKey = `state:${state}`;
      const stored = await env.OAUTH_KV.get(stateKey, 'json');
      if (!stored || stored.csrfToken !== csrfFromForm) {
        return new Response('Invalid CSRF token or state', { status: 403 });
      }
      // State is single-use.
      await env.OAUTH_KV.delete(stateKey);

      if (decision !== 'allow') {
        return new Response('Access denied', { status: 403 });
      }

      // Redirect the user to GitHub for upstream authentication.
      const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
      githubAuthUrl.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
      githubAuthUrl.searchParams.set('redirect_uri', `${url.origin}/callback`);
      githubAuthUrl.searchParams.set('scope', 'repo user:email');
      githubAuthUrl.searchParams.set('state', state);

      return Response.redirect(githubAuthUrl.toString(), 302);
    }

    // ---- GET /callback: GitHub redirects back here ----
    if (request.method === 'GET' && url.pathname === '/callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      if (!code || !state) {
        return new Response('Missing code or state', { status: 400 });
      }

      // Exchange the authorization code for a GitHub access token.
      const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: `${url.origin}/callback`,
        }),
      });
      const tokenData = await tokenResp.json();
      if (!tokenData.access_token) {
        return new Response('GitHub token exchange failed', { status: 502 });
      }

      // Complete the authorization. The upstream token is stored in `props`
      // so the API handler can use it later.
      return env.OAUTH_PROVIDER.completeAuthorization({
        request,
        userId: 'github-user', // You can fetch the real user id from GitHub if needed.
        scope: ['mcp:read', 'mcp:write'],
        props: { githubAccessToken: tokenData.access_token },
      });
    }

    return new Response('Not found', { status: 404 });
  },
};

// ============================================================
// 3. OAuthProvider configuration (single Worker: auth + resource)
// ============================================================
export default new OAuthProvider({
  // The path that serves the MCP endpoint. Requests here are validated
  // and then passed to `mcpApiHandler`.
  apiRoute: '/mcp',
  apiHandler: mcpApiHandler,

  // All other requests (the consent UI and callback) go here.
  defaultHandler: consentHandler,

  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
  clientRegistrationEndpoint: '/oauth/register',

  scopesSupported: ['mcp:read', 'mcp:write', 'offline_access'],
  resourceMetadata: {
    resource: 'https://github.miix.ir/mcp',
    authorization_servers: ['https://github.miix.ir'],
  },
  requiredScopes: ['mcp:read'],

  // Enables Dynamic Client Registration so MCP clients like Claude
  // can register themselves automatically.
  clientIdMetadataDocumentEnabled: true,

  // KV storage for tokens, codes, and state.
  kv: (env) => env.OAUTH_KV,
});

// ============================================================
// 4. Helpers
// ============================================================
function sanitizeHtml(str) {
  return str.replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;',
    '"': '&quot;', "'": '&#39;',
  }[c]));
}

function escapeAttr(str) {
  return str.replace(/["'&<>]/g, (c) => ({
    '"': '&quot;', "'": '&#39;', '&': '&amp;',
    '<': '&lt;', '>': '&gt;',
  }[c]));
}
