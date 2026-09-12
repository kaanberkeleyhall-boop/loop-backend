// ChatRoom — one Durable Object instance per live stream (keyed by stream id).
// Holds the ONLY source of truth for that stream's real-time chat and its
// real, live viewer count (== number of open WebSocket connections right
// now). Nothing here is simulated: a message only exists because a real
// connected client sent it, and the viewer count only ever reflects actual
// open sockets.
//
// Also runs the room's automated moderation ("Loop Security" bot persona):
// per-user flood limiting and a bad-word/spam-link filter that silently
// blocks a message (with a private notice back to the sender) and, after
// repeated violations, auto-mutes the sender for a short cooldown — plus
// real moderator/DJ actions (delete a message, mute, kick/ban) enforced
// here so they take effect immediately on any open connection.
const BOT_NAME = "Loop Security";
const FLOOD_WINDOW_MS = 10000;
const FLOOD_MAX_MESSAGES = 6;
const AUTO_MUTE_MS = 60000;
const AUTO_MUTE_AFTER_VIOLATIONS = 3;
const HISTORY_SIZE = 200;

// Deliberately simple, readable patterns rather than an external service —
// this runs on every message with no network round-trip. Covers obvious
// spam links and a short slur/profanity list; easy to extend.
const SPAM_PATTERNS = [/https?:\/\//i, /\bt\.me\//i, /\bdiscord\.gg\//i, /\bfree\s*(nitro|robux|gift\s*card)\b/i, /\bwww\./i];
const BLOCKED_WORDS = ["nigger", "faggot", "retard", "kike", "spic", "chink"]; // slurs — always blocked, no exceptions

function containsBlockedWord(text) {
  const lower = text.toLowerCase();
  return BLOCKED_WORDS.some((w) => lower.includes(w));
}
function looksLikeSpam(text) {
  return SPAM_PATTERNS.some((re) => re.test(text));
}

export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sockets = new Map(); // ws -> { userId, displayName, role }
    this.history = []; // recent messages, for mod-delete lookups
    this.violations = new Map(); // userId -> count
    this.mutedUntil = new Map(); // userId -> epoch ms
    this.recentTimestamps = new Map(); // userId -> [epoch ms, ...]
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

  sendTo(ws, payload) {
    try {
      ws.send(JSON.stringify(payload));
    } catch (e) {}
  }

  botMessage(text) {
    this.broadcast({
      type: "chat",
      message: { id: crypto.randomUUID(), userId: "bot", displayName: BOT_NAME, text, ts: Date.now(), fromBot: true },
    });
  }

  viewerCount() {
    return this.sockets.size;
  }

  socketsForUser(userId) {
    const out = [];
    for (const [ws, info] of this.sockets.entries()) {
      if (info.userId === userId) out.push(ws);
    }
    return out;
  }

  roleOf(userId) {
    for (const info of this.sockets.values()) {
      if (info.userId === userId) return info.role;
    }
    return null;
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

    // Internal RPC — the main Worker calls this right after recording a
    // real ban in D1, so anyone currently connected is disconnected at once
    // instead of staying in chat until they happen to refresh.
    if (url.pathname === "/kick" && request.method === "POST") {
      const { userId } = await request.json();
      const sockets = this.socketsForUser(userId);
      const displayName = sockets.length ? this.sockets.get(sockets[0])?.displayName : null;
      for (const ws of sockets) {
        this.sockets.delete(ws);
        try {
          ws.close(4001, "removed");
        } catch (e) {}
      }
      if (sockets.length) {
        this.botMessage(`${displayName || "A user"} was removed from chat by a moderator.`);
        this.broadcast({ type: "viewerCount", count: this.viewerCount() });
      }
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
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
      const role = url.searchParams.get("role") || "viewer"; // "dj" | "moderator" | "viewer"
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.accept();
      this.sockets.set(server, { userId, displayName, role });

      // Tell everyone (including the new arrival) the real, current count,
      // and tell the new arrival privately what their own role is so the
      // client knows whether to show moderation controls.
      this.broadcast({ type: "viewerCount", count: this.viewerCount() });
      this.sendTo(server, { type: "role", role });

      server.addEventListener("message", (event) => {
        let data;
        try {
          data = JSON.parse(event.data);
        } catch {
          return;
        }
        const info = this.sockets.get(server);
        if (!info) return;

        if (data?.type === "chat" && typeof data.text === "string" && data.text.trim()) {
          // Anyone can watch and see the real viewer count without an
          // account, but a chat message only exists because a signed-in
          // user sent it — an anonymous socket (no userId) is silently
          // dropped here rather than posted as "Guest".
          if (!info.userId) return;
          this.handleChatMessage(server, info, data.text.trim().slice(0, 140));
          return;
        }

        // Moderation actions — only ever honored from a socket the server
        // itself marked as "dj" or "moderator" at connect time (see the
        // /room route in index.js, which checks the real moderators/DJ
        // ownership in D1). A viewer's client sending these does nothing.
        if (info.role === "dj" || info.role === "moderator") {
          if (data?.type === "mod_delete" && data.messageId) {
            const found = this.history.find((m) => m.id === data.messageId);
            if (found) this.broadcast({ type: "chat_deleted", messageId: data.messageId });
            return;
          }
          if (data?.type === "mod_mute" && data.userId) {
            const minutes = Math.min(60, Math.max(1, Number(data.minutes) || 5));
            this.mutedUntil.set(data.userId, Date.now() + minutes * 60000);
            const target = [...this.sockets.values()].find((s) => s.userId === data.userId);
            this.botMessage(`${target?.displayName || "A user"} was muted for ${minutes} minute${minutes === 1 ? "" : "s"}.`);
            return;
          }
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

  handleChatMessage(server, info, text) {
    const now = Date.now();

    // Muted (manually, or by the auto-mod below) — rejected privately,
    // never broadcast.
    const mutedUntil = this.mutedUntil.get(info.userId) || 0;
    if (mutedUntil > now) {
      this.sendTo(server, { type: "chat_blocked", reason: "You're muted in this chat right now." });
      return;
    }

    // Flood / rate limiting — a simple per-user sliding window. This is
    // the "security bot" catching spam bots and flooders automatically,
    // with no moderator needing to be watching live.
    const stamps = (this.recentTimestamps.get(info.userId) || []).filter((t) => now - t < FLOOD_WINDOW_MS);
    stamps.push(now);
    this.recentTimestamps.set(info.userId, stamps);
    if (stamps.length > FLOOD_MAX_MESSAGES) {
      this.mutedUntil.set(info.userId, now + AUTO_MUTE_MS);
      this.sendTo(server, { type: "chat_blocked", reason: "You're sending messages too fast — muted for 60 seconds." });
      this.botMessage(`${info.displayName} was auto-muted for sending messages too fast.`);
      return;
    }

    // Bad-word / spam-link filter — blocked silently to the room, with a
    // private notice back to the sender. Repeated violations escalate to
    // an automatic mute, same as manual moderator action.
    if (containsBlockedWord(text) || looksLikeSpam(text)) {
      const count = (this.violations.get(info.userId) || 0) + 1;
      this.violations.set(info.userId, count);
      this.sendTo(server, { type: "chat_blocked", reason: "Your message was removed for violating chat guidelines." });
      if (count >= AUTO_MUTE_AFTER_VIOLATIONS) {
        this.mutedUntil.set(info.userId, now + AUTO_MUTE_MS);
        this.violations.set(info.userId, 0);
        this.botMessage(`${info.displayName} was auto-muted for repeated messages that broke chat guidelines.`);
      }
      return;
    }

    const message = { id: crypto.randomUUID(), userId: info.userId, displayName: info.displayName, text, ts: now };
    this.history.push(message);
    if (this.history.length > HISTORY_SIZE) this.history.shift();
    this.broadcast({ type: "chat", message });
  }
}
