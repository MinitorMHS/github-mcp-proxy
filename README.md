# github-mcp-proxy

A Cloudflare Worker that puts an OAuth 2.1 front door (with Dynamic Client
Registration) on GitHub's hosted MCP server, so clients like Claude.ai custom
connectors can connect. GitHub's remote MCP server accepts GitHub tokens but
does not offer DCR.

```
MCP client ──OAuth──► this Worker ──GitHub OAuth──► github.com
MCP client ──/mcp───► this Worker ──Bearer ghp_/gho_…──► api.githubcopilot.com/mcp
```

## Files

- `src/index.js`: the Worker (OAuth provider, GitHub login, proxy, cleanup).
- `src/pages.js`: the HTML pages only (consent page and error page). Edit the page markup and styles here.

## Flow

1. The client discovers `/.well-known/oauth-protected-resource/mcp`, registers at `/oauth/register`, and is sent to `/authorize`.
2. `/authorize` redirects straight to GitHub (PKCE, server-generated state bound to the browser with a `__Host-` cookie). By default there is no approve/deny page; set `REQUIRE_CONSENT=true` to add one (see below).
3. `/callback` exchanges the code, identifies the GitHub user, and issues the client its own tokens.
4. The GitHub token is encrypted (AES-256-GCM) into the grant props. Each `/mcp` request swaps the proxy token for the GitHub token and streams to `api.githubcopilot.com`.

## Access level

Read-only mode is enforced twice: the proxy forces `X-MCP-Readonly: true`, **and** GitHub is asked
for read-only scopes (`GITHUB_READONLY_SCOPES`, default `read:org read:user user:email read:packages read:project`),
so GitHub's own approval page and the resulting token match. Classic OAuth has no read-only form of `repo`,
so read-only connections cannot see **private** repositories (public ones work without any scope). For
read-only access to private repos, use a GitHub App with read-only repository permissions, or add `repo`
to `GITHUB_READONLY_SCOPES` and accept that GitHub's page will then ask for write access and the limit is
enforced by this proxy only.

If you authorized the OAuth App before, GitHub may reuse the earlier grant. After switching modes, check
`wrangler tail` for `GitHub granted scopes:`, and if it is broader than expected revoke the app at
github.com/settings/applications and connect again.

Write access (`mcp:write`) is granted by default. Set `READ_ONLY=true` to make every
connection read-only: the Worker then sends `X-MCP-Readonly: true`, so GitHub only
exposes read tools. Tokens issued before this logic existed carry no write flag and stay
read-only until their next refresh.

Clients may still send their own `X-MCP-Toolsets`, `X-MCP-Tools`, `X-MCP-Insiders` headers or use
`/mcp/x/<toolset>` paths; they pass through. See GitHub's `remote-server.md`.

## Read-only access to private repos (second GitHub App)

Classic OAuth Apps cannot give read-only access to private repositories (`repo` always includes write).
A **GitHub App** can, because its permissions are set per app. Give read-only connections their own app:

1. GitHub → Settings → Developer settings → GitHub Apps → New GitHub App.
2. Callback URL: `https://<your-domain>/callback`. Webhook: untick *Active*. Leave *Expire user authorization tokens* on (the Worker refreshes them).
3. Repository permissions, all **Read-only**: Contents and Metadata at minimum, plus whatever you want the AI to see (Issues, Pull requests, Actions, Discussions, Commit statuses, ...). Leave write permissions off.
4. Install the app on your account (all repositories, or selected). A GitHub App user token only sees repositories where the app is installed.
5. Generate a client secret, then:
   ```bash
   npx wrangler secret put GITHUB_READONLY_CLIENT_ID
   npx wrangler secret put GITHUB_READONLY_CLIENT_SECRET
   ```

When both are set, every read-only connection (READ_ONLY=true, or "Read-only" on the consent page) signs in
through that app, and the refresh of its expiring token uses the same app. Read & write connections keep using
`GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`. GitHub Apps ignore the `scope` parameter, so `GITHUB_READONLY_SCOPES`
does not apply to them. A tool that needs a permission the app lacks will return an error until you add it in the
app's settings.

## Browser support

The sign-in flow only uses plain redirects, `SameSite=Lax` cookies and a form with no scripts, so it needs no
browser-specific code. It was tested end to end over HTTPS, including the cross-site round trip back from the
OAuth server, in Chromium, Firefox 159 and WebKitGTK 2.52 (the WebKit engine; not Safari itself).

## Optional consent page

`REQUIRE_CONSENT=true` shows an Approve / Deny page before the GitHub redirect. It names the client,
shows where tokens will be sent, and lets you choose Read-only or Read & write (hidden when
`READ_ONLY=true`). It is the only protection against the attack below if you do not set
`ALLOWED_REDIRECT_URIS`; with the allowlist set it adds no extra security, only a click.
The page deliberately sends no `form-action` CSP directive: Chromium applies that directive to the
redirect after the form POST and would block the jump to GitHub (tested in Chromium).

## Protecting a no-consent setup

Because nothing asks the user to approve, anyone could register a client with their own
`redirect_uri` and send you a link to `/authorize`; if you are already signed in to GitHub
they would receive tokens for your account. Set **`ALLOWED_REDIRECT_URIS`** to the callback(s)
of the clients you actually use. The Worker logs every `redirect_uri` it sees (`wrangler tail`)
so you can copy the right value.

## Setup

1. Create a GitHub **OAuth App** (or GitHub App). Callback URL: `https://<your-domain>/callback`.
2. Edit `PUBLIC_ORIGIN` at the top of `src/index.js` and attach that domain to the Worker.
3. Install and set secrets:
   ```bash
   npm install
   npx wrangler secret put GITHUB_CLIENT_ID
   npx wrangler secret put GITHUB_CLIENT_SECRET
   openssl rand -base64 32 | npx wrangler secret put ENCRYPTION_KEY
   npx wrangler deploy
   ```
4. Add the connector URL `https://<your-domain>/mcp` in your MCP client.

## Optional variables

| Variable | Effect |
|---|---|
| `ALLOWED_REDIRECT_URIS` | Comma-separated redirect URIs (exact or prefix match) that clients may use. **Strongly recommended.** Empty = any. |
| `REQUIRE_CONSENT` | `true` = show the Approve / Deny page (default: off). |
| `GITHUB_READONLY_CLIENT_ID` / `GITHUB_READONLY_CLIENT_SECRET` | Secrets for the optional read-only GitHub App (see above). |
| `READ_ONLY` | `true` = no client can get write access. |
| `ALLOWED_GITHUB_USERS` | Comma-separated GitHub logins allowed to authorize. Empty = anyone. **Recommended for personal deployments.** |
| `GITHUB_READONLY_SCOPES` | Scopes requested in read-only mode. Default: `read:org read:user user:email read:packages read:project` (no `repo`). |
| `COMPRESS_LISTS` | gzip for answers (see Troubleshooting): default on for clients that accept gzip and for Claude Code; `always` = every client; `false` = off. |
| `MCP_TOOLSETS` | Default `X-MCP-Toolsets` sent to GitHub (e.g. `repos,issues,pull_requests`) when the client sends none. A smaller tool list means a much smaller `tools/list` answer. |
| `UPSTREAM_TIMEOUT_MS` | How long to wait for GitHub to start answering before returning 504 (default 40000). |
| `GITHUB_SCOPES` | Space-separated scopes requested from GitHub. Defaults to GitHub's own default set. Add e.g. `workflow` if you see scope challenges in the logs. |
| `MCP_LOCKDOWN` | `true` sends `X-MCP-Lockdown: true` (hides public issue content from users without push access). |

## GitHub Apps (expiring tokens)

If you use a GitHub App with expiring user tokens, the Worker stores the refresh
token and renews the GitHub token when the client refreshes its proxy token. OAuth
App tokens do not expire and need no refresh.

## Troubleshooting ("connected, tools fetch failed")

"Connected" only proves the sign-in worked; the tool list is a separate request. To see which step fails,
run the probe **from the machine and network your MCP client uses**:

```bash
npm install
npm run probe -- https://<your-domain>/mcp
```

It signs in through the proxy with the official MCP client (it prints an address to open in a browser), lists
the tools, and reports the failing step. Then check the Worker side with `npx wrangler tail`: every proxied
request logs one line, for example

```
mcp POST /mcp rpc=tools/list -> 200 text/event-stream 48ms
mcp POST /mcp rpc=tools/list -> 403 application/json 120ms
mcp upstream 403 body: {"message": ...}
```

- **No HTTP answer in the probe** (`fetch failed`, `ENOTFOUND`, timeouts to connect): that machine cannot reach the proxy address.
- **`MCP error -32001: Request timed out`** is the *client's* own timeout: no complete answer arrived in time. The `wrangler tail` lines for `rpc=tools/list` say why:

| What the log shows | Meaning |
|---|---|
| `-> sent to GitHub` and nothing else, then `GitHub sent no answer within 40000ms` (client gets a 504) | GitHub never answered. Wait/retry, or check the token and Copilot access. |
| `-> 200 ...` then `still streaming ...; waiting for more data from GitHub` | GitHub started answering and stopped sending. |
| `-> 200 ...` then `still streaming ...; GitHub data is ready but the connection back to the client is not taking it` | GitHub is fine; the path between Cloudflare and the client is too slow or stuck for a response this size. |
| `body complete: N bytes in Xms` | The whole answer left the Worker. If the client still timed out, the loss is after the Worker. |
| `client went away after N bytes` | The client hung up (usually its own timeout) while data was still being sent. |
| `-> 4xx/5xx` plus `mcp upstream NNN body: ...` | GitHub refused the call; the body says why. |
| `upstream unreachable` | The Worker could not reach GitHub. |

Set `UPSTREAM_TIMEOUT_MS` to change how long the Worker waits for GitHub to start answering (default 40000).

### When the answer leaves the Worker but never arrives

If the logs show `body complete` (the whole answer left the Worker) and the client still times out, the loss is on
the way back to the client. `npm run probe` then runs a **download test** automatically (`--net` runs it always):
it fetches generated data of growing size from `/mcp/__selftest` (needs your sign-in; served by the Worker itself,
GitHub is not involved), once as an event stream and once as JSON, and says whether big responses stall, at what
size, and whether event streams are treated differently from JSON.

**Compression.** Event streams are not compressed by default, and tool lists and tool results can be large, so the
Worker gzips the single answer to ordinary requests (`tools/list`, `tools/call`, `resources/*`, `prompts/*`) when
(a) GitHub did not compress it, (b) the client can decode gzip, and (c) the answer is between 8 KB and 1 MB. It
reads the answer, compresses it and sends it with `Content-Encoding: gzip`; if the answer does not finish within
20 s (or exceeds 8 MB) it streams the original untouched. The log line reads `compressed answer: 126939 -> N bytes`;
when it does not compress, `not compressed (...)` says why.

"Can decode gzip" means the client's own `Accept-Encoding` includes gzip. **Claude Code is a special case**: it sends
`Accept-Encoding: identity` on purpose, but its fetch-based HTTP stack decodes gzip anyway (tested with Claude Code
2.1.317, which then lists all tools), so clients whose User-Agent starts with `claude-code/` are compressed for too.
`COMPRESS_LISTS=always` compresses for every client regardless of what it asked for; `COMPRESS_LISTS=false` turns
compression off.

Find a toolset combination that works from your network with
`npm run probe -- https://<your-domain>/mcp --toolsets repos,issues,pull_requests` (it prints tool count and size).

Workarounds that need no code: connect through a narrower address such as `https://<your-domain>/mcp/x/issues`
(or `/mcp/x/repos`, `/mcp/readonly`), or set `MCP_TOOLSETS`. GitHub then sends far fewer tools, so the answer is a
fraction of the size (and the model reads fewer tokens).

The proxy never hands the client a link to GitHub's API host: redirects are followed inside the Worker, and URLs in
`Location`, `Link` and `WWW-Authenticate` headers are rewritten to the proxy's own address, so a client that can only
reach the proxy never needs to reach anything else. Upstream cookies are dropped.

## Operations

- A daily cron runs the library's `purgeExpiredData()` sweep. DCR clients expire after 90 days on their own.
- If GitHub rejects the stored token (revoked), the grant is revoked and the client is sent back through authorization.
- Every proxied request is logged (method, path, JSON-RPC method, status, time); error bodies are logged truncated.
- GitHub scope challenges (HTTP 403) are logged with the missing scope and returned without the upstream `WWW-Authenticate` header.
- Orgs with OAuth App access restrictions must approve the app: `https://github.com/organizations/<ORG>/settings/oauth_application_policy`.
