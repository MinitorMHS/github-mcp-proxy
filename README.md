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

1. The client discovers `/.well-known/oauth-protected-resource/mcp`, registers at `/oauth/register`, and sends the user to `/authorize`.
2. **Consent page.** The user sees which client is asking and where tokens will be sent, and picks *Read-only* or *Read & write*. The decision is bound to the browser with `__Host-` cookies (CSRF / confused-deputy protection).
3. The Worker redirects to GitHub (PKCE, bound state), then `/callback` exchanges the code and identifies the GitHub user.
4. The GitHub token is encrypted (AES-256-GCM) into the grant props. Each `/mcp` request swaps the proxy token for the GitHub token and streams to `api.githubcopilot.com`.

## Access levels

`mcp:read` is required for every connection. Without `mcp:write` the Worker sends
`X-MCP-Readonly: true`, so GitHub only exposes read tools. Tokens issued before
this feature existed carry no write flag and stay read-only until their next refresh.

Clients may still send their own `X-MCP-Toolsets`, `X-MCP-Tools`, `X-MCP-Insiders` headers or use
`/mcp/x/<toolset>` paths; they pass through. See GitHub's `remote-server.md`.

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
| `ALLOWED_GITHUB_USERS` | Comma-separated GitHub logins allowed to authorize. Empty = anyone. **Recommended for personal deployments.** |
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
