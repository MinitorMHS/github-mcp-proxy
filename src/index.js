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
// 2. OAuth handler: redirect straight to GitHub, no consent UI
// ============================================================
const oauthHandler = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ---- GET /authorize: parse, validate, redirect to GitHub ----
    if (request.method === 'GET' && url.pathname === '/authorize') {
      let authRequest;
      try {
        authRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
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
          return new Response(
            `<h1>Authorization Error</h1><p>${escapeHtml(error.description || 'Unknown error')}</p>`,
            { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
          );
        }
        throw error;
      }

      if (!env.GITHUB_CLIENT_ID) {
        return new Response('GITHUB_CLIENT_ID not configured', { status: 500 });
      }

      // Skip the consent page — GitHub will show its own authorization screen.
      // The state param (issued by Claude's MCP client) already provides CSRF protection.
      const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
      githubAuthUrl.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
      githubAuthUrl.searchParams.set('redirect_uri', `${url.origin}/callback`);
      githubAuthUrl.searchParams.set('scope', 'repo user:email');
      githubAuthUrl.searchParams.set('state', authRequest.state);

      console.log('Redirecting to GitHub', { state: authRequest.state });
      return Response.redirect(githubAuthUrl.toString(), 302);
    }

    // ---- GET /callback: GitHub redirects here with code ----
    if (request.method === 'GET' && url.pathname === '/callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const error = url.searchParams.get('error');

      if (error) {
        const desc = url.searchParams.get('error_description') || error;
        return new Response(`GitHub auth error: ${escapeHtml(desc)}`, { status: 400 });
      }
      if (!code || !state) {
        return new Response('Missing code or state', { status: 400 });
      }

      const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
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
        const desc = tokenData.error_description || tokenData.error || 'unknown';
        return new Response(`GitHub token exchange failed: ${escapeHtml(desc)}`, { status: 502 });
      }

      console.log('GitHub token acquired, completing authorization');

      // Library looks up pending auth by state, issues token to Claude,
      // returns a 302 redirect to Claude's localhost callback.
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
  defaultHandler: oauthHandler,

  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/oauth/token',
  clientRegistrationEndpoint: '/oauth/register',

  scopesSupported: ['mcp:read', 'mcp:write', 'offline_access'],
  resourceMetadata: {
    resource: 'https://github.miix.ir/mcp',
    authorization_servers: ['https://github.miix.ir'],
  },
  requiredScopes: ['mcp:read'],

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
