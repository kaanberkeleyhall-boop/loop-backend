// ChatRoom — one Durable Object instance per live stream (keyed by stream id).
// Holds the ONLY source of truth for that stream's real-time chat and its
// real, live viewer count (== number of open WebSocket connections right
// now). Nothing here is simulated: a message only exists because a real
// connected client sent it, and the viewer count only ever reflects actual
// open sockets.
export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sockets = new Map(); // ws -> { userId, displayName }
  }

  broadcast(payload) {
    const msg = JSON.stringify(payload);
    for (const ws of this.sockets.keys()) {
      try {
        ws.send(msg);
      } catch (e) {
        // dead socket — will be cleaned up by its own close/error handler
      }
    }
  }

  viewerCount() {
    return this.sockets.size;
  }

  async fetch(request) {
    const url = new URL(request.url);

    // Internal RPC used by the main Worker (e.g. after a Stripe webhook
    // confirms a real payment) to push an event into this room.
    if (url.pathname === "/broadcast" && request.method === "POST") {
      const payload = await request.json();
      this.broadcast(payload);
      return new Response(JSON.stringify({ ok: true, viewerCount: this.viewerCount() }), {
        headers: { "content-type": "application/json" },
      });
    }

    if (url.pathname === "/count") {
      return new Response(JSON.stringify({ viewerCount: this.viewerCount() }), {
        headers: { "content-type": "application/json" },
      });
    }

    if (url.pathname === "/room") {
      if (request.headers.get("Upgrade") !== "websocket") {
        return new Response("Expected WebSocket", { status: 426 });
      }
      const userId = url.searchParams.get("userId") || "";
      const displayName = url.searchParams.get("displayName") || "Someone";
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.accept();
      this.sockets.set(server, { userId, displayName });

      // Tell everyone (including the new arrival) the real, current count.
      this.broadcast({ type: "viewerCount", count: this.viewerCount() });

      server.addEventListener("message", (event) => {
        let data;
        try {
          data = JSON.parse(event.data);
        } catch {
          return;
        }
        if (data?.type === "chat" && typeof data.text === "string" && data.text.trim()) {
          const info = this.sockets.get(server);
          // Anyone can watch and see the real viewer count without an
          // account, but a chat message only exists because a signed-in
          // user sent it — an anonymous socket (no userId) is silently
          // dropped here rather than posted as "Guest".
          if (!info || !info.userId) return;
          this.broadcast({
            type: "chat",
            message: {
              id: crypto.randomUUID(),
              userId: info.userId,
              displayName: info.displayName,
              text: data.text.trim().slice(0, 140),
              ts: Date.now(),
            },
          });
        }
      });

      const cleanup = () => {
        this.sockets.delete(server);
        this.broadcast({ type: "viewerCount", count: this.viewerCount() });
      };
      server.addEventListener("close", cleanup);
      server.addEventListener("error", cleanup);

      return new Response(null, { status: 101, webSocket: client });
    }

    return new Response("Not found", { status: 404 });
  }
}
