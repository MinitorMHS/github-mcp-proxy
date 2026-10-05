export default {
  async fetch(request, env) {
    const incomingAuth = request.headers.get("Authorization") || "";
    const expectedAuth = `Bearer ${env.GITHUB_PAT}`;

    // 1. Reject anything without the exact Bearer <PAT>
    if (!timingSafeEqual(incomingAuth, expectedAuth)) {
      console.log("Rejected request from", request.headers.get("CF-Connecting-IP"));
      return new Response("Unauthorized", { status: 401 });
    }

    // 2. Optional: In-Worker rate limit (secondary safety net)
    if (env.MCP_RL) {
      const { success } = await env.MCP_RL.limit({
        key: request.headers.get("CF-Connecting-IP") || "unknown",
      });
      if (!success) {
        return new Response("Rate limited", { status: 429 });
      }
    }

    const TARGET_HOST = "api.githubcopilot.com";
    const url = new URL(request.url);
    const targetUrl = new URL(`https://${TARGET_HOST}${url.pathname}${url.search}`);

    const proxyRequest = new Request(targetUrl, {
      method: request.method,
      headers: request.headers,
      body: request.body,
      redirect: "manual",
    });

    // 3. Force Host, re-inject Authorization, and strip proxy metadata
    proxyRequest.headers.set("Host", TARGET_HOST);
    proxyRequest.headers.set("Authorization", expectedAuth);
    proxyRequest.headers.delete("CF-Connecting-IP");
    proxyRequest.headers.delete("X-Forwarded-For");
    proxyRequest.headers.delete("CF-Connecting-IP");
    proxyRequest.headers.delete("CF-Connecting-Port");
    proxyRequest.headers.delete("CF-EW-Via");
    proxyRequest.headers.delete("CF-Ray");
    proxyRequest.headers.delete("X-Forwarded-For");
    proxyRequest.headers.delete("X-Forwarded-Proto");
    proxyRequest.headers.delete("X-Real-IP");

    const response = await fetch(proxyRequest);

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  },
};

// Constant-time string comparison
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}