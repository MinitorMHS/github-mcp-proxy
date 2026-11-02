import { OAuthProvider, AuthorizationError } from '@cloudflare/workers-oauth-provider';

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
// 2. API handler (resource server): proxies to GitHub MCP
// ============================================================
const mcpApiHandler = {
  async fetch(request, env, ctx) {
    const encryptedToken = ctx.props?.encryptedGithubToken;
    if (!encryptedToken) {
      return new Response('Missing upstream token', { status: 401 });
    }

    let upstreamToken;
    try {
      upstreamToken = await decryptToken(encryptedToken, env.ENCRYPTION_KEY);
    } catch (err) {
      console.error('Token decryption failed', err.message);
      return new Response('Token decryption failed', { status: 500 });
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
// 3. OAuth handler
// ============================================================
const oauthHandler = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Rate limit /oauth/register to prevent DCR spam
    if (url.pathname === '/oauth/register' && env.REG_RL) {
      const { success } = await env.REG_RL.limit({
        key: request.headers.get('CF-Connecting-IP') || 'unknown',
      });
      if (!success) return new Response('Rate limited', { status: 429 });
    }

    // ---- GET /authorize ----
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

      // Store the parsed authRequest for the callback step
      await env.OAUTH_KV.put(
        `authreq:${authRequest.state}`,
        JSON.stringify(authRequest),
        { expirationTtl: 600 }
      );

      // Request all scopes the official GitHub MCP server advertises.
      // GitHub will only grant scopes the OAuth App is allowed to request;
      // any org-restricted scope may remain "pending" until an admin approves.
      const GITHUB_SCOPES = [
        'repo',
        'read:org',
        'read:user',
        'user:email',
        'read:packages',
        'write:packages',
        'read:project',
        'project',
        'gist',
        'notifications',
      ].join(' ');

      const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
      githubAuthUrl.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
      githubAuthUrl.searchParams.set('redirect_uri', `${url.origin}/callback`);
      githubAuthUrl.searchParams.set('scope', GITHUB_SCOPES);
      githubAuthUrl.searchParams.set('state', authRequest.state);

      return Response.redirect(githubAuthUrl.toString(), 302);
    }

    // ---- GET /callback ----
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

      const stored = await env.OAUTH_KV.get(`authreq:${state}`);
      if (!stored) {
        return new Response('Authorization request expired or invalid state', { status: 400 });
      }
      const authRequest = JSON.parse(stored);

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

      // Log the scopes GitHub actually granted (useful for debugging)
      if (tokenData.scope) {
        console.log('GitHub granted scopes:', tokenData.scope);
      }

      // Encrypt the GitHub token before storing in KV via props
      let encryptedGithubToken;
      try {
        encryptedGithubToken = await encryptToken(
          tokenData.access_token,
          env.ENCRYPTION_KEY
        );
      } catch (err) {
        console.error('Token encryption failed', err.message);
        return new Response('Token encryption failed', { status: 500 });
      }

      try {
        const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
          request: authRequest,
          userId: 'github-user',
          metadata: {},
          scope: authRequest.scope,
          props: { encryptedGithubToken },
        });

        await env.OAUTH_KV.delete(`authreq:${state}`);
        return Response.redirect(redirectTo, 302);
      } catch (err) {
        console.error('completeAuthorization failed', err.message);
        return new Response(`Authorization completion failed: ${escapeHtml(err.message)}`, {
          status: 500,
        });
      }
    }

    return new Response('Not found', { status: 404 });
  },
};

// ============================================================
// 4. Cron cleanup handler (daily 03:00 UTC)
// ============================================================
async function cleanupHandler(env) {
  let deleted = 0;

  // 1. Orphaned authreq entries (belt-and-suspenders; TTL usually handles these)
  let cursor;
  do {
    const list = await env.OAUTH_KV.list({ prefix: 'authreq:', cursor });
    for (const key of list.keys) {
      const val = await env.OAUTH_KV.get(key.name);
      if (!val) {
        await env.OAUTH_KV.delete(key.name);
        deleted++;
      }
    }
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);

  // 2. Orphaned DCR clients (only if the library exposes expiresAt)
  const clients = await env.OAUTH_KV.list({ prefix: '__client:' });
  const grants = await env.OAUTH_KV.list({ prefix: '__grant:' });

  const grantedClientIds = new Set();
  for (const g of grants.keys) {
    const grant = await env.OAUTH_KV.get(g.name, 'json');
    if (grant?.clientId) grantedClientIds.add(grant.clientId);
  }

  for (const c of clients.keys) {
    const client = await env.OAUTH_KV.get(c.name, 'json');
    if (
      client?.clientId &&
      !grantedClientIds.has(client.clientId) &&
      client.expiresAt &&
      client.expiresAt < Date.now()
    ) {
      await env.OAUTH_KV.delete(c.name);
      deleted++;
    }
  }

  console.log(`KV cleanup: deleted ${deleted} orphaned keys`);
}

// ============================================================
// 5. OAuthProvider + Worker exports
// ============================================================
const provider = new OAuthProvider({
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

export default {
  async fetch(request, env, ctx) {
    return provider.fetch(request, env, ctx);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanupHandler(env));
  },
};

// ============================================================
// 6. Helpers
// ============================================================
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;',
    '"': '&quot;', "'": '&#39;',
  }[c]));
}
