# github-mcp-proxy

A Cloudflare Worker that puts an OAuth 2.1 front door (with Dynamic Client
Registration) on GitHub's hosted MCP server, so clients like Claude.ai custom
connectors can connect. GitHub's remote MCP server accepts GitHub tokens but
does not offer DCR.

```
MCP client ──OAuth──► this Worker ──GitHub OAuth──► github.com
MCP client ──/mcp───► this Worker ──Bearer ghp_/gho_…──► api.githubcopilot.com/mcp
```

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
| `READ_ONLY` | `true` = no client can get write access. |
| `ALLOWED_GITHUB_USERS` | Comma-separated GitHub logins allowed to authorize. Empty = anyone. **Recommended for personal deployments.** |
| `GITHUB_READONLY_SCOPES` | Scopes requested in read-only mode. Default: `read:org read:user user:email read:packages read:project` (no `repo`). |
| `GITHUB_SCOPES` | Space-separated scopes requested from GitHub. Defaults to GitHub's own default set. Add e.g. `workflow` if you see scope challenges in the logs. |
| `MCP_LOCKDOWN` | `true` sends `X-MCP-Lockdown: true` (hides public issue content from users without push access). |

## GitHub Apps (expiring tokens)

If you use a GitHub App with expiring user tokens, the Worker stores the refresh
token and renews the GitHub token when the client refreshes its proxy token. OAuth
App tokens do not expire and need no refresh.

## Operations

- A daily cron runs the library's `purgeExpiredData()` sweep. DCR clients expire after 90 days on their own.
- If GitHub rejects the stored token (revoked), the grant is revoked and the client is sent back through authorization.
- GitHub scope challenges (HTTP 403) are logged with the missing scope and returned without the upstream `WWW-Authenticate` header.
- Orgs with OAuth App access restrictions must approve the app: `https://github.com/organizations/<ORG>/settings/oauth_application_policy`.
