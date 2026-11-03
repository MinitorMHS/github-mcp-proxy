import {
  OAuthProvider,
  AuthorizationError,
  OAuthError,
  authorizationErrorRedirect,
  getOAuthApi,
} from '@cloudflare/workers-oauth-provider';
import { consentPage, errorPage } from './pages.js';

// ============================================================
// 0. Configuration
// ============================================================

// Public origin this Worker is served from. Must match the custom domain you
// attach to the Worker and the callback URL on your GitHub OAuth App.
const PUBLIC_ORIGIN = 'https://github.miix.ir';
const MCP_PATH = '/mcp';

const TARGET_HOST = 'api.githubcopilot.com';
const UPSTREAM_PUBLIC = `https://${TARGET_HOST}`; // how GitHub writes its own URLs
const UPSTREAM_ORIGIN = UPSTREAM_PUBLIC; // where requests are sent
const MAX_UPSTREAM_REDIRECTS = 5;
// How long to wait for GitHub to START answering (headers). Streaming bodies are not cut off.
const DEFAULT_UPSTREAM_TIMEOUT_MS = 40000;
// tools/list answers are big and compress ~6:1, but event streams are not compressed by default.
const COMPRESS_MIN_BYTES = 8192;
const COMPRESS_WAIT_MS = 20000;
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

// Scopes requested from GitHub when the connection is read-only (READ_ONLY=true, or
// "Read-only" chosen on the consent page). GitHub's `repo` scope always includes write
// access and classic OAuth has no read-only variant of it, so it is left out: private
// repositories are not reachable in this mode, public ones still are. Override with
// GITHUB_READONLY_SCOPES (adding `repo` brings private repos back, but then GitHub's own
// page asks for write access and the read-only limit is enforced by this proxy only).
const DEFAULT_READONLY_GITHUB_SCOPES =
  'read:org read:user user:email read:packages read:project';

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

// Optional second GitHub app used for read-only connections (see README). A GitHub App
// with read-only repository permissions is the only way to get read access to private
// repos without write access. Both variables must be set for it to be used.
function hasReadOnlyApp(env) {
  return Boolean(env.GITHUB_READONLY_CLIENT_ID && env.GITHUB_READONLY_CLIENT_SECRET);
}
function githubCredentials(env, readOnlyApp) {
  return readOnlyApp && hasReadOnlyApp(env)
    ? { id: env.GITHUB_READONLY_CLIENT_ID, secret: env.GITHUB_READONLY_CLIENT_SECRET }
    : { id: env.GITHUB_CLIENT_ID, secret: env.GITHUB_CLIENT_SECRET };
}

function githubTokenRequest(env, params, readOnlyApp = false) {
  const creds = githubCredentials(env, readOnlyApp);
  return fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'User-Agent': GITHUB_UA,
    },
    body: JSON.stringify({
      client_id: creds.id,
      client_secret: creds.secret,
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
async function buildProps(env, tokenData, login, readOnlyApp = false) {
  const props = {
    encryptedGithubToken: await encryptToken(tokenData.access_token, env.ENCRYPTION_KEY),
    login,
  };
  if (readOnlyApp) props.ro = true; // refresh must use the read-only app's credentials
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
    resp = await githubTokenRequest(env, { grant_type: 'refresh_token', refresh_token: refreshToken }, props.ro === true);
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

  const fresh = await buildProps(env, data, props.login, props.ro === true);
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
// Passes a response body through unchanged while logging how much was delivered and when,
// so a stalled download can be told apart from a slow or silent upstream.
function countedBody(body, label, started) {
  if (!body) return body;
  const reader = body.getReader();
  let bytes = 0;
  let firstByteAt = null;
  let lastChunkAt = Date.now();
  let waitingSince = null; // set while we are waiting on GitHub for the next chunk
  let finished = false;
  let ticks = 0;
  const stop = () => {
    finished = true;
    clearInterval(progress);
  };
  // Only logs when a body is slow (every 5s) and says which side is holding things up.
  // The stream is read on demand: if no read is pending, nobody is asking for more data,
  // so the connection back to the client is the bottleneck; if a read is pending, GitHub is.
  const progress = setInterval(() => {
    if (finished || ++ticks > 12) return clearInterval(progress);
    const who = waitingSince !== null
      ? `waiting for more data from GitHub (${Date.now() - waitingSince}ms so far)`
      : 'GitHub data is ready but the connection back to the client is not taking it';
    console.warn(`${label} still streaming after ${Date.now() - started}ms: ${bytes} bytes sent, last data ${Date.now() - lastChunkAt}ms ago; ${who}`);
  }, 5000);

  return new ReadableStream(
    {
      async pull(controller) {
        waitingSince = Date.now();
        try {
          const { done, value } = await reader.read();
          waitingSince = null;
          if (done) {
            stop();
            console.log(`${label} body complete: ${bytes} bytes in ${Date.now() - started}ms (first byte at ${firstByteAt}ms)`);
            controller.close();
            return;
          }
          lastChunkAt = Date.now();
          if (firstByteAt === null) firstByteAt = lastChunkAt - started;
          bytes += value.byteLength;
          controller.enqueue(value);
        } catch (err) {
          stop();
          console.warn(`${label} body cut off after ${bytes} bytes at ${Date.now() - started}ms: ${err?.message ?? err}`);
          controller.error(err);
        }
      },
      cancel(reason) {
        stop();
        console.warn(`${label} client went away after ${bytes} bytes at ${Date.now() - started}ms`);
        return reader.cancel(reason);
      },
    },
    { highWaterMark: 0 }
  );
}

// Same host as the upstream (also matches the overridden origin used in tests).
function isUpstreamUrl(u) {
  return u.hostname === TARGET_HOST || u.origin === UPSTREAM_ORIGIN;
}

// Sends the request upstream. Redirects that stay on the upstream host are followed
// here, so the client never receives a Location pointing at a host it may not reach.
async function fetchUpstream(method, pathAndQuery, headers, body, signal) {
  let m = method;
  let b = body;
  let h = headers;
  let target = UPSTREAM_ORIGIN + pathAndQuery;
  for (let hop = 0; ; hop++) {
    const resp = await fetch(target, { method: m, headers: h, body: b, redirect: 'manual', signal });
    if (![301, 302, 303, 307, 308].includes(resp.status) || hop >= MAX_UPSTREAM_REDIRECTS) return resp;
    const location = resp.headers.get('Location');
    if (!location) return resp;
    let next;
    try {
      next = new URL(location, target);
    } catch {
      return resp;
    }
    if (!isUpstreamUrl(next)) return resp; // some other host: not ours to follow
    if (resp.status === 303 || ((resp.status === 301 || resp.status === 302) && m === 'POST')) {
      m = 'GET'; // standard redirect semantics: method becomes GET, body is dropped
      b = undefined;
      h = new Headers(h);
      h.delete('Content-Length');
      h.delete('Content-Type');
    }
    console.log(`mcp upstream redirect ${resp.status} -> ${next.pathname}`);
    resp.body?.cancel();
    target = UPSTREAM_ORIGIN + next.pathname + next.search;
  }
}

// Copy of the upstream response headers that is safe to hand to the client.
function proxyResponseHeaders(upstreamHeaders) {
  const h = new Headers(upstreamHeaders);
  for (const name of [
    'Set-Cookie', 'Connection', 'Keep-Alive', 'Transfer-Encoding', 'TE', 'Trailer',
    'Upgrade', 'Proxy-Authenticate', 'Proxy-Authorization',
  ]) {
    h.delete(name);
  }
  // Any absolute link to the upstream host would send the client straight to it.
  for (const name of ['Location', 'Content-Location', 'Link', 'WWW-Authenticate']) {
    const v = h.get(name);
    if (v && v.includes(UPSTREAM_PUBLIC)) h.set(name, v.split(UPSTREAM_PUBLIC).join(PUBLIC_ORIGIN));
  }
  return h;
}

// JSON-RPC method name(s) of a request body, for logging only (params are never read).
function rpcMethod(buf) {
  if (!buf || buf.byteLength === 0 || buf.byteLength > 1_000_000) return '-';
  try {
    const j = JSON.parse(new TextDecoder().decode(buf));
    return Array.isArray(j) ? j.map((x) => x.method).join(',') : j.method ?? '-';
  } catch {
    return '-';
  }
}

// Cloudflare normalizes the Accept-Encoding header the Worker sees; the client's own value is in
// request.cf.clientAcceptEncoding, so prefer that.
function clientAcceptsGzip(request) {
  const original = request.cf?.clientAcceptEncoding ?? request.headers.get('Accept-Encoding') ?? '';
  return /\bgzip\b/i.test(original);
}

// id of a single JSON-RPC request body (null if it is not one).
function rpcId(buf) {
  if (!buf || buf.byteLength === 0 || buf.byteLength > 1_000_000) return null;
  try {
    const j = JSON.parse(new TextDecoder().decode(buf));
    return j && !Array.isArray(j) && 'id' in j ? j.id : null;
  } catch {
    return null;
  }
}

// True once the text holds a complete SSE event carrying the JSON-RPC answer for `id`.
function answerSeen(text, id) {
  const events = text.split(/\r?\n\r?\n/);
  events.pop(); // the last piece is incomplete (or empty)
  for (const ev of events) {
    const data = ev
      .split(/\r?\n/)
      .filter((l) => l.startsWith('data:'))
      .map((l) => l.slice(5).replace(/^ /, ''))
      .join('\n');
    if (!data) continue;
    try {
      const m = JSON.parse(data);
      if (m && m.id === id && ('result' in m || 'error' in m)) return true;
    } catch {
      // not JSON: ignore
    }
  }
  return false;
}

// Stream that replays what was already read, then carries on with the rest.
function replayStream(chunks, pending, reader) {
  let i = 0;
  return new ReadableStream(
    {
      async pull(controller) {
        if (i < chunks.length) return controller.enqueue(chunks[i++]);
        const r = pending ? await pending : await reader.read();
        pending = null;
        if (r.done) controller.close();
        else controller.enqueue(r.value);
      },
      cancel(reason) {
        return reader.cancel(reason);
      },
    },
    { highWaterMark: 0 }
  );
}

// Reads a single-answer event stream (tools/list) completely and returns it gzip-compressed.
// If the answer does not finish in time, returns the original stream untouched instead.
async function gzipSingleAnswer(body, id) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  const chunks = [];
  let text = '';
  let bytes = 0;
  let complete = false;
  let pending = null;
  const deadline = Date.now() + COMPRESS_WAIT_MS;
  const TIMEOUT = Symbol('timeout');
  while (!complete) {
    const left = deadline - Date.now();
    if (left <= 0) break;
    pending = pending || reader.read();
    let timer;
    const r = await Promise.race([pending, new Promise((res) => { timer = setTimeout(() => res(TIMEOUT), left); })]);
    clearTimeout(timer);
    if (r === TIMEOUT) break;
    pending = null;
    if (r.done) { complete = true; break; }
    chunks.push(r.value);
    bytes += r.value.byteLength;
    text += decoder.decode(r.value, { stream: true });
    if (answerSeen(text, id)) {
      complete = true;
      reader.cancel().catch(() => {}); // the answer is complete; don't wait for the server to close
    }
  }
  if (!complete) return { stream: replayStream(chunks, pending, reader) };
  const raw = new Blob(chunks);
  if (bytes < COMPRESS_MIN_BYTES) return { raw: await raw.arrayBuffer(), bytes };
  const gz = await new Response(raw.stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer();
  return { gz, bytes };
}

// Authenticated download test used by test/probe.mjs: returns N bytes of incompressible-ish
// text without contacting GitHub, so a network problem can be told apart from an MCP problem.
const SELFTEST_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function selfTestResponse(url) {
  const asked = parseInt(url.searchParams.get('bytes') || '1024', 10);
  const total = Math.min(Math.max(Number.isFinite(asked) ? asked : 1024, 64), 600000);
  const json = url.searchParams.get('type') === 'json';
  const head = json ? '{"pad":"' : 'event: message\ndata: ';
  const tail = json ? '"}' : '\n\n';
  const padLen = Math.max(total - head.length - tail.length, 0);
  const pad = new Uint8Array(padLen);
  for (let off = 0; off < padLen; off += 65536) {
    const chunk = crypto.getRandomValues(new Uint8Array(Math.min(65536, padLen - off)));
    for (let i = 0; i < chunk.length; i++) pad[off + i] = SELFTEST_ALPHABET.charCodeAt(chunk[i] & 63);
  }
  const enc = new TextEncoder();
  const body = new Uint8Array(total);
  body.set(enc.encode(head), 0);
  body.set(pad, head.length);
  body.set(enc.encode(tail), head.length + padLen);
  return new Response(body, {
    headers: {
      'Content-Type': json ? 'application/json' : 'text/event-stream',
      'Cache-Control': 'no-store, no-transform',
    },
  });
}

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

    const self = new URL(request.url);
    if (request.method === 'GET' && self.pathname === `${MCP_PATH}/__selftest`) return selfTestResponse(self);

    let upstreamToken;
    try {
      upstreamToken = await decryptToken(props.encryptedGithubToken, env.ENCRYPTION_KEY);
    } catch (err) {
      console.error('Token decryption failed', err.message);
      return new Response('Token decryption failed', { status: 500 });
    }

    const url = new URL(request.url);
    const started = Date.now();

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
    // A smaller tool list means a smaller answer to tools/list (and fewer tokens spent on it).
    if (env.MCP_TOOLSETS && !headers.has('X-MCP-Toolsets')) headers.set('X-MCP-Toolsets', env.MCP_TOOLSETS);

    // MCP request bodies are small JSON; buffering lets a redirect be replayed.
    const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
    const bodyBuf = hasBody ? await request.arrayBuffer() : undefined;
    const rpc = rpcMethod(bodyBuf);

    const label = `mcp ${request.method} ${url.pathname} rpc=${rpc}`;
    console.log(`${label} -> sent to GitHub`);

    // Give GitHub a bounded time to start answering; once headers arrive the body streams freely.
    const timeoutMs = Number(env.UPSTREAM_TIMEOUT_MS) || DEFAULT_UPSTREAM_TIMEOUT_MS;
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), timeoutMs);
    let upstream;
    try {
      upstream = await fetchUpstream(request.method, url.pathname + url.search, headers, bodyBuf, abort.signal);
    } catch (err) {
      if (abort.signal.aborted) {
        console.error(`${label} -> GitHub sent no answer within ${timeoutMs}ms`);
        return new Response(
          JSON.stringify({ error: 'upstream_timeout', message: `GitHub did not answer within ${Math.round(timeoutMs / 1000)} seconds.` }),
          { status: 504, headers: { 'Content-Type': 'application/json' } }
        );
      }
      console.error(`${label} -> upstream unreachable: ${err.message}`);
      return new Response(
        JSON.stringify({ error: 'upstream_unreachable', message: 'The proxy could not reach GitHub.' }),
        { status: 502, headers: { 'Content-Type': 'application/json' } }
      );
    } finally {
      clearTimeout(timer);
    }

    const contentType = upstream.headers.get('Content-Type') || '-';
    console.log(
      `${label} -> ${upstream.status} ${contentType} headers after ${Date.now() - started}ms` +
        ` (encoding=${upstream.headers.get('Content-Encoding') ?? 'none'}, length=${upstream.headers.get('Content-Length') ?? 'streamed'})`
    );
    // (405 on the GET stream is normal for stateless MCP servers, not worth a warning.)
    if (upstream.status >= 400 && upstream.status !== 405 && !contentType.includes('event-stream')) {
      // The reason for a failure is usually in GitHub's error body.
      const snippet = await upstream.clone().text().then((t) => t.slice(0, 300), () => '');
      console.warn(`mcp upstream ${upstream.status} body: ${snippet}`);
    }

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
      if (dead) {
        if (props.grantId && props.userId) {
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
      // The token is fine, so re-authorizing would not help: pass GitHub's answer on
      // as it is (without a challenge that would send the client around in circles).
      console.warn('GitHub returned 401 although the token is still valid');
      const h = proxyResponseHeaders(upstream.headers);
      h.delete('WWW-Authenticate');
      return new Response(upstream.body, { status: 401, statusText: upstream.statusText, headers: h });
    }

    const responseHeaders = proxyResponseHeaders(upstream.headers);
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

    // Event streams are not compressed by default, and the tool list is large. When GitHub did not
    // compress it and the client accepts gzip, send it compressed (COMPRESS_LISTS=false turns this off).
    if (
      env.COMPRESS_LISTS !== 'false' && rpc === 'tools/list' && upstream.status === 200 && upstream.body &&
      contentType.includes('text/event-stream') && !upstream.headers.get('Content-Encoding') &&
      clientAcceptsGzip(request)
    ) {
      const out = await gzipSingleAnswer(upstream.body, rpcId(bodyBuf));
      if (out.stream) {
        console.warn(`${label} answer did not finish within ${COMPRESS_WAIT_MS}ms; sending it uncompressed`);
        return new Response(countedBody(out.stream, label, started), {
          status: upstream.status, statusText: upstream.statusText, headers: responseHeaders,
        });
      }
      responseHeaders.delete('Content-Length');
      if (out.gz) {
        responseHeaders.set('Content-Encoding', 'gzip');
        responseHeaders.append('Vary', 'Accept-Encoding');
        console.log(`${label} compressed answer: ${out.bytes} -> ${out.gz.byteLength} bytes (${Date.now() - started}ms)`);
        return new Response(out.gz, {
          status: upstream.status, statusText: upstream.statusText, headers: responseHeaders, encodeBody: 'manual',
        });
      }
      console.log(`${label} answer is small (${out.bytes} bytes), not compressed`);
      return new Response(out.raw, { status: upstream.status, statusText: upstream.statusText, headers: responseHeaders });
    }

    return new Response(countedBody(upstream.body, label, started), {
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
        }, data?.readOnlyApp === true);
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
        const props = await buildProps(env, tokenData, ghUser.login, data?.readOnlyApp === true);
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
  const canWrite = scope.includes('mcp:write');
  const readOnlyApp = !canWrite && hasReadOnlyApp(env);
  const upstream = await helpers.beginUpstream(
    { ...authRequest, scope },
    { data: { codeVerifier: pkce.verifier, readOnlyApp }, headers: baseHeaders }
  );
  const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
  githubAuthUrl.searchParams.set('client_id', githubCredentials(env, readOnlyApp).id);
  githubAuthUrl.searchParams.set('redirect_uri', `${url.origin}/callback`);
  githubAuthUrl.searchParams.set(
    'scope',
    canWrite
      ? env.GITHUB_SCOPES || DEFAULT_GITHUB_SCOPES
      : env.GITHUB_READONLY_SCOPES ?? DEFAULT_READONLY_GITHUB_SCOPES
  );
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
