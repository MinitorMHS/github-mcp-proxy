import { OAuthProvider, AuthorizationError } from '@cloudflare/workers-oauth-provider';

// ============================================================
// 1. API handler (resource server): proxies to GitHub MCP
// ============================================================
const mcpApiHandler = {
  async fetch(request, env, ctx) {
    const upstreamToken = ctx.props?.githubAccessToken;
    if (!upstreamToken) {
      return new Response('Missing upstream token', { status: 401 });
    }

    // Optional: rate limit backstop
    if (env.MCP_RL) {
      const { success } = await env.MCP_RL.limit({
        key: request.headers.get('CF-Connecting-IP') || 'unknown',
      });
      if (!success) return new Response('Rate limited', { status: 429 });
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
    proxyRequest.headers.set('Authorization', `Bearer ${upstreamToken}`);

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
const consentHandler = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ---- GET /authorize: render consent page ----
    if (request.method === 'GET' && url.pathname === '/authorize') {
      let authRequest;
      try {
        authRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
      } catch (error) {
        if (error instanceof AuthorizationError) {
          // Safe redirect back to client with error details
          if (error.redirectUri) {
            const redirect = new URL(error.redirectUri);
            redirect.searchParams.set('error', error.code);
            redirect.searchParams.set('error_description', error.description);
            if (error.state) redirect.searchParams.set('state', error.state);
            if (error.issuer) redirect.searchParams.set('iss', error.issuer);
            return Response.redirect(redirect.toString(), 302);
          }
          // No safe redirect — render error locally
          return new Response(
            `<h1>Authorization Error</h1><p>${escapeHtml(error.description || 'Unknown error')}</p>`,
            { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
          );
        }
        // Unexpected error — re-throw so Cloudflare logs it
        throw error;
      }

      // CSRF protection: random token in __Host- cookie + hidden form field
      const csrfToken = crypto.randomUUID();
      const csrfCookieName = '__Host-csrf';
      const csrfCookie = `${csrfCookieName}=${csrfToken}; Path=/; Secure; HttpOnly; SameSite=Lax`;

      // State binding: store CSRF token in KV with short TTL
      const stateKey = `state:${authRequest.state}`;
      await env.OAUTH_KV.put(
        stateKey,
        JSON.stringify({ csrfToken }),
        { expirationTtl: 600 }
      );

      // Sanitize user-controlled fields
      const clientName = escapeHtml(authRequest.clientName || 'Unknown Client');
      const stateEscaped = escapeAttr(authRequest.state);

      const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Authorize ${clientName}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 480px; margin: 4rem auto; color: #222; }
    .card { border: 1px solid #ddd; padding: 2rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    h2 { margin-top: 0; }
    button { padding: 0.5rem 1.25rem; margin-right: 0.75rem; border-radius: 6px; border: 1px solid #ccc; cursor: pointer; font-size: 1rem; }
    button[value="allow"] { background: #1f883d; color: #fff; border-color: #1f883d; }
    button[value="deny"]  { background: #f6f8fa; color: #222; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Authorize ${clientName}</h2>
    <p><strong>${clientName}</strong> is requesting access to your GitHub Copilot MCP data via this proxy.</p>
    <form method="POST" action="/authorize">
      <input type="hidden" name="state" value="${stateEscaped}">
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
          'Content-Security-Policy':
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
          'Set-Cookie': csrfCookie,
          'Referrer-Policy': 'no-referrer',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
        },
      });
    }

    // ---- POST /authorize: handle consent decision ----
    if (request.method === 'POST' && url.pathname === '/authorize') {
      const form = await request.formData();
      const state = form.get('state');
      const csrfFromForm = form.get('csrf');
      const decision = form.get('decision');

      // Validate CSRF token against KV
      const stateKey = `state:${state}`;
      const stored = await env.OAUTH_KV.get(stateKey, 'json');
      if (!stored || stored.csrfToken !== csrfFromForm) {
        return new Response('Invalid CSRF token or expired state', { status: 403 });
      }
      // Single-use: delete state immediately
      await env.OAUTH_KV.delete(stateKey);

      if (decision !== 'allow') {
        return new Response('Access denied', { status: 403 });
      }

      // Redirect user to GitHub for upstream authentication
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
      const error = url.searchParams.get('error');

      if (error) {
        return new Response(`GitHub auth error: ${escapeHtml(error)}`, { status: 400 });
      }
      if (!code || !state) {
        return new Response('Missing code or state', { status: 400 });
      }

      // Exchange the authorization code for a GitHub access token
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

      if (!tokenResp.ok) {
        return new Response('GitHub token exchange HTTP error', { status: 502 });
      }

      const tokenData = await tokenResp.json();
      if (!tokenData.access_token) {
        return new Response('GitHub token exchange failed', { status: 502 });
      }

      // Complete the authorization — store upstream token in props
      return env.OAUTH_PROVIDER.completeAuthorization({
        request,
        userId: 'github-user',
        scope: ['mcp:read', 'mcp:write'],
        props: { githubAccessToken: tokenData.access_token },
      });
    }

    return new Response('Not found', { status: 404 });
  },
};

// ============================================================
// 3. OAuthProvider configuration
// ============================================================
export default new OAuthProvider({
  apiRoute: '/mcp',
  apiHandler: mcpApiHandler,
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

  // Disable CIMD — rely on DCR instead.
  // Claude's CIMD document exceeds the library's 5 KB limit and triggers
  // a CimdFetchError → 1101. DCR is registered dynamically per client.
  clientIdMetadataDocumentEnabled: false,

  kv: (env) => env.OAUTH_KV,
});

// ============================================================
// 4. Helpers
// ============================================================
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;',
    '"': '&quot;', "'": '&#39;',
  }[c]));
}

function escapeAttr(str) {
  return String(str).replace(/["'&<>]/g, (c) => ({
    '"': '&quot;', "'": '&#39;', '&': '&amp;',
    '<': '&lt;', '>': '&gt;',
  }[c]));
}
