// Loop API — Cloudflare Worker backend.
//
// Real accounts, real streams (via Cloudflare Stream Live), real chat +
// viewer counts (via the ChatRoom Durable Object), real follows, and real
// credit-card tips (via Stripe Checkout + webhook confirmation). Nothing
// here is seeded or simulated — every row in D1 was created by an actual
// API call from a signed-in user.
import { ChatRoom } from "./chatRoom.js";
export { ChatRoom };

const TOKEN_TTL_DAYS = 30;

// ── small helpers ─────────────────────────────────────────────────────────
function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  return arr;
}
function genId(prefix) {
  return (prefix ? prefix + "_" : "") + crypto.randomUUID().replace(/-/g, "");
}
function genToken() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}
function safeJson(text, fallback) {
  try {
    return JSON.parse(text);
  } catch {
    return fallback;
  }
}
async function pbkdf2Hash(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256);
  return { hashHex: bytesToHex(new Uint8Array(bits)), saltHex: bytesToHex(salt) };
}

function json(data, status, extraHeaders) {
  return new Response(JSON.stringify(data), { status: status || 200, headers: { "content-type": "application/json", ...(extraHeaders || {}) } });
}
function err(message, status) {
  return json({ error: message }, status || 400);
}
function corsHeaders(env, request) {
  const origin = request.headers.get("Origin") || "";
  const allowed = env.ALLOWED_ORIGIN || "*";
  const allowOrigin = allowed === "*" ? "*" : origin === allowed ? origin : allowed;
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    Vary: "Origin",
  };
}

async function getUserFromRequest(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return null;
  return env.DB.prepare(
    `SELECT u.* FROM auth_tokens t JOIN users u ON u.id = t.user_id WHERE t.token = ? AND t.expires_at > datetime('now')`
  )
    .bind(token)
    .first();
}

function publicUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    city: row.city || "",
    bio: row.bio || "",
    isDj: !!row.is_dj,
    verified: row.dj_verification_status === "approved",
    genres: safeJson(row.genres, []),
    bpmMin: row.bpm_min,
    bpmMax: row.bpm_max,
    followerCount: row.follower_count || 0,
    createdAt: row.created_at,
  };
}
function isAdminEmail(env, email) {
  if (!env.ADMIN_EMAILS || !email) return false;
  const list = env.ADMIN_EMAILS.split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
  return list.includes(email.trim().toLowerCase());
}
function privateUser(row, env) {
  return {
    ...publicUser(row),
    email: row.email,
    mediaAccessEnabled: !!row.media_access_enabled,
    twoFactorEnabled: !!row.two_factor_enabled,
    verificationStatus: row.dj_verification_status || "unverified",
    isAdmin: env ? isAdminEmail(env, row.email) : false,
  };
}
function publicVerification(row) {
  return {
    id: row.id,
    userId: row.user_id,
    equipment: row.equipment,
    platform: row.platform,
    experience: row.experience || "",
    videoUid: row.video_uid,
    status: row.status,
    reviewerNote: row.reviewer_note || "",
    createdAt: row.created_at,
    reviewedAt: row.reviewed_at,
  };
}
function publicStream(row) {
  return {
    id: row.id,
    djId: row.dj_id,
    title: row.title,
    genres: safeJson(row.genres, []),
    bpmMin: row.bpm_min,
    bpmMax: row.bpm_max,
    isPrivate: !!row.is_private,
    status: row.status,
    city: row.city || "",
    startTime: row.start_time,
    endTime: row.end_time,
    playbackUid: row.playback_uid,
    peakViewerCount: row.peak_viewer_count || 0,
    createdAt: row.created_at,
  };
}
// Ingest secrets — only ever attached to a response for the stream's own
// owning DJ (see the /api/streams routes below), never in the public shape.
// playerUrl is NOT a secret (viewers need it to watch) and is attached
// separately, publicly, wherever a stream is live.
function ownerStreamFields(row) {
  return { whipUrl: row.whip_url, rtmpsUrl: row.rtmps_url, streamKey: row.stream_key };
}
function playerUrlFor(row, env) {
  return cfPlayerUrl(env, row.playback_uid);
}
function publicRequest(row) {
  return {
    id: row.id,
    sessionId: row.stream_id,
    requestedByUserId: row.requested_by_user_id,
    query: row.query,
    amountPledged: row.amount_pledged_cents / 100,
    status: row.status,
    createdAt: row.created_at,
  };
}
function publicTip(row) {
  return { id: row.id, fromUserId: row.from_user_id, toDjId: row.to_dj_id, sessionId: row.stream_id, amount: row.amount_cents / 100, message: row.message, createdAt: row.created_at };
}

// ── Stripe (plain REST — no SDK dependency) ──────────────────────────────
function flattenForm(obj, prefix, out) {
  out = out || [];
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    const key = prefix ? `${prefix}[${k}]` : k;
    if (Array.isArray(v)) {
      v.forEach((item, i) => {
        if (item && typeof item === "object") flattenForm(item, `${key}[${i}]`, out);
        else out.push([`${key}[${i}]`, String(item)]);
      });
    } else if (typeof v === "object") {
      flattenForm(v, key, out);
    } else {
      out.push([key, String(v)]);
    }
  }
  return out;
}
async function stripeRequest(env, method, path, body) {
  if (!env.STRIPE_SECRET_KEY) throw new Error("Stripe isn't configured on the server yet (STRIPE_SECRET_KEY missing).");
  const headers = { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` };
  let payload;
  if (body) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    payload = flattenForm(body)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");
  }
  const resp = await fetch(`https://api.stripe.com/v1${path}`, { method, headers, body: payload });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data?.error?.message || "Stripe request failed");
  return data;
}
async function verifyStripeSignature(payloadText, sigHeader, secret) {
  if (!sigHeader) return false;
  const parts = Object.fromEntries(sigHeader.split(",").map((p) => p.split("=")));
  if (!parts.t || !parts.v1) return false;
  const signedPayload = `${parts.t}.${payloadText}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigBytes = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signedPayload));
  return bytesToHex(new Uint8Array(sigBytes)) === parts.v1;
}
async function markTipPaid(env, tip) {
  if (tip.status === "paid") return;
  await env.DB.prepare(`UPDATE tips SET status='paid', paid_at=datetime('now') WHERE id=?`).bind(tip.id).run();
  if (tip.stream_id) {
    try {
      const dj = await env.DB.prepare(`SELECT display_name FROM users WHERE id=?`).bind(tip.to_dj_id).first();
      const fromUser = tip.from_user_id ? await env.DB.prepare(`SELECT display_name FROM users WHERE id=?`).bind(tip.from_user_id).first() : null;
      const id = env.CHAT_ROOM.idFromName(tip.stream_id);
      const stub = env.CHAT_ROOM.get(id);
      await stub.fetch("https://do/broadcast", {
        method: "POST",
        body: JSON.stringify({
          type: "tip",
          payload: { id: tip.id, amount: tip.amount_cents / 100, tierName: tip.tier_name, message: tip.message, djName: dj?.display_name, fromName: fromUser?.display_name || "Someone" },
        }),
      });
    } catch (e) {
      // Best-effort — the tip is already marked paid either way.
    }
  }
}

// ── Cloudflare Stream (Live) ─────────────────────────────────────────────
async function cfStreamRequest(env, method, path, body) {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) throw new Error("Cloudflare Stream isn't configured on the server yet (CF_API_TOKEN / CF_ACCOUNT_ID missing).");
  const resp = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}${path}`, {
    method,
    headers: { Authorization: `Bearer ${env.CF_API_TOKEN}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await resp.json();
  if (!data.success) throw new Error((data.errors && data.errors[0] && data.errors[0].message) || "Cloudflare Stream request failed");
  return data.result;
}
async function goLiveInternal(env, streamRow) {
  const live = await cfStreamRequest(env, "POST", "/stream/live_inputs", { meta: { name: streamRow.title }, recording: { mode: "automatic" } });
  await env.DB.prepare(`UPDATE streams SET status='live', start_time=datetime('now'), live_input_uid=?, playback_uid=?, whip_url=?, rtmps_url=?, stream_key=? WHERE id=?`)
    .bind(live.uid, live.uid, live.webRTC?.url || null, live.rtmps?.url || null, live.rtmps?.streamKey || null, streamRow.id)
    .run();
  const row = await env.DB.prepare(`SELECT * FROM streams WHERE id=?`).bind(streamRow.id).first();
  const out = publicStream(row);
  out.whipUrl = row.whip_url;
  out.rtmpsUrl = row.rtmps_url;
  out.streamKey = row.stream_key;
  out.playerUrl = cfPlayerUrl(env, row.playback_uid);
  return out;
}
async function liveViewerCount(env, streamId) {
  try {
    const id = env.CHAT_ROOM.idFromName(streamId);
    const stub = env.CHAT_ROOM.get(id);
    const r = await stub.fetch("https://do/count");
    const { viewerCount } = await r.json();
    return viewerCount;
  } catch {
    return 0;
  }
}
// Same Cloudflare Stream player works for a live input's playback uid AND a
// plain uploaded (VOD) uid — used both for watching a live set and for an
// admin reviewing a DJ verification video.
function cfPlayerUrl(env, uid) {
  return env.CF_STREAM_CUSTOMER_CODE && uid ? `https://customer-${env.CF_STREAM_CUSTOMER_CODE}.cloudflarestream.com/${uid}/iframe` : null;
}

// ── router ────────────────────────────────────────────────────────────────
async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (path === "/" ) return json({ ok: true, service: "loop-api" });

  // Auth ---------------------------------------------------------------
  if (path === "/api/signup" && method === "POST") {
    const body = await request.json();
    const email = (body.email || "").trim().toLowerCase();
    const displayName = (body.displayName || "").trim();
    const password = body.password || "";
    if (!email || !displayName || password.length < 6) return err("A display name, valid email, and a password of 6+ characters are required.");
    const existing = await env.DB.prepare(`SELECT id FROM users WHERE email=?`).bind(email).first();
    if (existing) return err("An account with that email already exists — try logging in instead.");
    const base = (body.username || displayName).toLowerCase().replace(/[^a-z0-9]/g, "") || "dj";
    let finalUsername = base;
    let suffix = 0;
    while (await env.DB.prepare(`SELECT id FROM users WHERE username=?`).bind(finalUsername).first()) {
      suffix += 1;
      finalUsername = `${base}${suffix}`;
    }
    const { hashHex, saltHex } = await pbkdf2Hash(password);
    const id = genId("u");
    await env.DB.prepare(`INSERT INTO users (id, email, username, display_name, password_hash, password_salt, city, is_dj) VALUES (?,?,?,?,?,?,?,?)`)
      .bind(id, email, finalUsername, displayName, hashHex, saltHex, body.city || "", body.isDj ? 1 : 0)
      .run();
    const token = genToken();
    const expires = new Date(Date.now() + TOKEN_TTL_DAYS * 24 * 3600 * 1000).toISOString();
    await env.DB.prepare(`INSERT INTO auth_tokens (token, user_id, expires_at) VALUES (?,?,?)`).bind(token, id, expires).run();
    const user = await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(id).first();
    return json({ token, user: privateUser(user, env) });
  }

  if (path === "/api/login" && method === "POST") {
    const body = await request.json();
    const email = (body.email || "").trim().toLowerCase();
    const password = body.password || "";
    const user = await env.DB.prepare(`SELECT * FROM users WHERE email=?`).bind(email).first();
    if (!user) return err("Incorrect email or password.", 401);
    const { hashHex } = await pbkdf2Hash(password, user.password_salt);
    if (hashHex !== user.password_hash) return err("Incorrect email or password.", 401);
    const token = genToken();
    const expires = new Date(Date.now() + TOKEN_TTL_DAYS * 24 * 3600 * 1000).toISOString();
    await env.DB.prepare(`INSERT INTO auth_tokens (token, user_id, expires_at) VALUES (?,?,?)`).bind(token, user.id, expires).run();
    return json({ token, user: privateUser(user, env) });
  }

  if (path === "/api/logout" && method === "POST") {
    const auth = request.headers.get("Authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (token) await env.DB.prepare(`DELETE FROM auth_tokens WHERE token=?`).bind(token).run();
    return json({ ok: true });
  }

  if (path === "/api/me" && method === "GET") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Not signed in.", 401);
    return json({ user: privateUser(user, env) });
  }

  if (path === "/api/me" && method === "PATCH") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Not signed in.", 401);
    const body = await request.json();
    const fields = [];
    const binds = [];
    const set = (col, val) => {
      fields.push(`${col}=?`);
      binds.push(val);
    };
    if (body.displayName !== undefined) set("display_name", body.displayName);
    if (body.city !== undefined) set("city", body.city);
    if (body.bio !== undefined) set("bio", body.bio);
    if (body.isDj !== undefined) set("is_dj", body.isDj ? 1 : 0);
    if (body.genres !== undefined) set("genres", JSON.stringify(body.genres));
    if (body.bpmMin !== undefined) set("bpm_min", body.bpmMin);
    if (body.bpmMax !== undefined) set("bpm_max", body.bpmMax);
    if (body.mediaAccessEnabled !== undefined) set("media_access_enabled", body.mediaAccessEnabled ? 1 : 0);
    if (body.twoFactorEnabled !== undefined) set("two_factor_enabled", body.twoFactorEnabled ? 1 : 0);
    if (fields.length) {
      binds.push(user.id);
      await env.DB.prepare(`UPDATE users SET ${fields.join(", ")} WHERE id=?`).bind(...binds).run();
    }
    const updated = await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(user.id).first();
    return json({ user: privateUser(updated, env) });
  }

  if (path === "/api/users" && method === "GET") {
    const isDj = url.searchParams.get("isDj");
    let q = "SELECT * FROM users";
    const binds = [];
    if (isDj) {
      q += " WHERE is_dj=1";
    }
    q += " ORDER BY follower_count DESC LIMIT 100";
    const { results } = await env.DB.prepare(q).bind(...binds).all();
    return json({ users: results.map(publicUser) });
  }

  if (path.match(/^\/api\/users\/[^/]+$/) && method === "GET") {
    const idOrUsername = path.split("/")[3];
    const row = await env.DB.prepare(`SELECT * FROM users WHERE id=? OR username=?`).bind(idOrUsername, idOrUsername).first();
    if (!row) return err("User not found.", 404);
    return json({ user: publicUser(row) });
  }

  // Streams --------------------------------------------------------------
  if (path === "/api/streams" && method === "GET") {
    const status = url.searchParams.get("status");
    const djIdParam = url.searchParams.get("djId");
    const requester = await getUserFromRequest(request, env);
    let djId = djIdParam;
    let isOwner = false;
    if (djIdParam === "me") {
      if (!requester) return err("Sign in required.", 401);
      djId = requester.id;
      isOwner = true;
    } else if (djIdParam && requester && djIdParam === requester.id) {
      isOwner = true;
    }
    let q = "SELECT * FROM streams WHERE 1=1";
    const binds = [];
    if (status) {
      q += " AND status=?";
      binds.push(status);
    }
    if (djId) {
      q += " AND dj_id=?";
      binds.push(djId);
    }
    if (!isOwner) q += " AND is_private=0";
    q += " ORDER BY start_time DESC LIMIT 100";
    const { results } = await env.DB.prepare(q).bind(...binds).all();
    const streams = [];
    for (const row of results) {
      const s = publicStream(row);
      s.viewerCount = s.status === "live" ? await liveViewerCount(env, s.id) : 0;
      if (s.status === "live") s.playerUrl = playerUrlFor(row, env);
      // Ingest secrets (WHIP URL / stream key) only ever go to the owning DJ,
      // and only while the stream is actually live — never to viewers.
      if (isOwner && s.status === "live") Object.assign(s, ownerStreamFields(row));
      streams.push(s);
    }
    return json({ streams });
  }

  if (path === "/api/streams" && method === "POST") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    if (!user.is_dj) return err("Only DJ accounts can create streams. Sign up as a DJ to get started.", 403);
    const body = await request.json();
    if (body.goLiveNow && user.dj_verification_status !== "approved") {
      return err("Your DJ account needs to be verified before you can go live. Submit your verification from Studio.", 403);
    }
    const id = genId("stream");
    await env.DB.prepare(`INSERT INTO streams (id, dj_id, title, genres, bpm_min, bpm_max, is_private, status, city, start_time) VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .bind(id, user.id, (body.title || "Untitled set").slice(0, 140), JSON.stringify(body.genres || []), body.bpmMin || null, body.bpmMax || null, body.isPrivate ? 1 : 0, "scheduled", body.city || user.city || "", body.startTime || null)
      .run();
    let row = await env.DB.prepare(`SELECT * FROM streams WHERE id=?`).bind(id).first();
    let stream = publicStream(row);
    if (body.goLiveNow) {
      stream = await goLiveInternal(env, row);
    }
    return json({ stream });
  }

  if (path.match(/^\/api\/streams\/[^/]+\/go-live$/) && method === "POST") {
    const streamId = path.split("/")[3];
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    const row = await env.DB.prepare(`SELECT * FROM streams WHERE id=?`).bind(streamId).first();
    if (!row) return err("Stream not found.", 404);
    if (row.dj_id !== user.id) return err("Forbidden.", 403);
    if (user.dj_verification_status !== "approved") {
      return err("Your DJ account needs to be verified before you can go live. Submit your verification from Studio.", 403);
    }
    const stream = await goLiveInternal(env, row);
    return json({ stream });
  }

  if (path.match(/^\/api\/streams\/[^/]+\/end$/) && method === "POST") {
    const streamId = path.split("/")[3];
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    const row = await env.DB.prepare(`SELECT * FROM streams WHERE id=?`).bind(streamId).first();
    if (!row) return err("Stream not found.", 404);
    if (row.dj_id !== user.id) return err("Forbidden.", 403);
    if (row.live_input_uid) {
      try {
        await cfStreamRequest(env, "DELETE", `/stream/live_inputs/${row.live_input_uid}`);
      } catch (e) {}
    }
    await env.DB.prepare(`UPDATE streams SET status='ended', end_time=datetime('now') WHERE id=?`).bind(streamId).run();
    const updated = await env.DB.prepare(`SELECT * FROM streams WHERE id=?`).bind(streamId).first();
    return json({ stream: publicStream(updated) });
  }

  if (path.match(/^\/api\/streams\/[^/]+\/room$/) && method === "GET") {
    const streamId = path.split("/")[3];
    const token = url.searchParams.get("token");
    // Anyone can watch a live set and see the real viewer count without an
    // account — a token just attaches a real identity to the socket so chat
    // sends (gated in the ChatRoom Durable Object itself) know who sent them.
    const row = token
      ? await env.DB.prepare(`SELECT u.* FROM auth_tokens t JOIN users u ON u.id=t.user_id WHERE t.token=? AND t.expires_at>datetime('now')`).bind(token).first()
      : null;
    const stream = await env.DB.prepare(`SELECT id FROM streams WHERE id=?`).bind(streamId).first();
    if (!stream) return err("Stream not found.", 404);
    const id = env.CHAT_ROOM.idFromName(streamId);
    const stub = env.CHAT_ROOM.get(id);
    const doUrl = new URL(request.url);
    doUrl.pathname = "/room";
    doUrl.searchParams.set("userId", row ? row.id : "");
    doUrl.searchParams.set("displayName", row ? row.display_name : "Guest");
    return stub.fetch(new Request(doUrl.toString(), request));
  }

  if (path.match(/^\/api\/streams\/[^/]+\/requests$/) && method === "GET") {
    const streamId = path.split("/")[3];
    const { results } = await env.DB.prepare(`SELECT * FROM track_requests WHERE stream_id=? ORDER BY created_at DESC`).bind(streamId).all();
    return json({ requests: results.map(publicRequest) });
  }

  if (path.match(/^\/api\/streams\/[^/]+\/requests$/) && method === "POST") {
    const streamId = path.split("/")[3];
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    const body = await request.json();
    if (!body.query || !body.query.trim()) return err("A request needs some text.");
    const id = genId("req");
    await env.DB.prepare(`INSERT INTO track_requests (id, stream_id, requested_by_user_id, query, amount_pledged_cents, status) VALUES (?,?,?,?,?, 'pending')`)
      .bind(id, streamId, user.id, body.query.trim().slice(0, 200), Math.round((body.amountPledged || 0) * 100))
      .run();
    const row = await env.DB.prepare(`SELECT * FROM track_requests WHERE id=?`).bind(id).first();
    return json({ request: publicRequest(row) });
  }

  if (path.match(/^\/api\/streams\/[^/]+\/requests\/[^/]+$/) && method === "PATCH") {
    const parts = path.split("/");
    const streamId = parts[3];
    const reqId = parts[5];
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    const stream = await env.DB.prepare(`SELECT * FROM streams WHERE id=?`).bind(streamId).first();
    if (!stream || stream.dj_id !== user.id) return err("Forbidden.", 403);
    const body = await request.json();
    await env.DB.prepare(`UPDATE track_requests SET status=? WHERE id=?`).bind(body.status, reqId).run();
    const row = await env.DB.prepare(`SELECT * FROM track_requests WHERE id=?`).bind(reqId).first();
    return json({ request: publicRequest(row) });
  }

  if (path.match(/^\/api\/streams\/[^/]+$/) && method === "GET") {
    const streamId = path.split("/")[3];
    const row = await env.DB.prepare(`SELECT * FROM streams WHERE id=?`).bind(streamId).first();
    if (!row) return err("Stream not found.", 404);
    const stream = publicStream(row);
    stream.viewerCount = stream.status === "live" ? await liveViewerCount(env, streamId) : 0;
    if (stream.status === "live") stream.playerUrl = playerUrlFor(row, env);
    const requester = await getUserFromRequest(request, env);
    if (requester && requester.id === row.dj_id) Object.assign(stream, ownerStreamFields(row));
    const dj = await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(row.dj_id).first();
    return json({ stream, dj: publicUser(dj) });
  }

  // Follows ----------------------------------------------------------------
  if (path === "/api/follows/mine" && method === "GET") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    const { results } = await env.DB.prepare(`SELECT dj_id FROM follows WHERE follower_id=?`).bind(user.id).all();
    return json({ djIds: results.map((r) => r.dj_id) });
  }
  if (path.match(/^\/api\/follows\/[^/]+$/) && method === "POST") {
    const djId = path.split("/")[3];
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    await env.DB.prepare(`INSERT OR IGNORE INTO follows (follower_id, dj_id) VALUES (?,?)`).bind(user.id, djId).run();
    await env.DB.prepare(`UPDATE users SET follower_count = follower_count + 1 WHERE id=?`).bind(djId).run();
    return json({ ok: true });
  }
  if (path.match(/^\/api\/follows\/[^/]+$/) && method === "DELETE") {
    const djId = path.split("/")[3];
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    const { meta } = await env.DB.prepare(`DELETE FROM follows WHERE follower_id=? AND dj_id=?`).bind(user.id, djId).run();
    if (meta?.changes) await env.DB.prepare(`UPDATE users SET follower_count = MAX(0, follower_count - 1) WHERE id=?`).bind(djId).run();
    return json({ ok: true });
  }

  // DJ verification ----------------------------------------------------------
  // A DJ account can't go live until an admin approves a submitted
  // verification (equipment + platform/software questions plus a short
  // video), reviewed in the admin dashboard below.
  if (path === "/api/dj-verification/upload-url" && method === "POST") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    if (!user.is_dj) return err("Only DJ accounts submit verification.", 403);
    const direct = await cfStreamRequest(env, "POST", "/stream/direct_upload", {
      maxDurationSeconds: 300,
      requireSignedURLs: false,
      meta: { name: `verification-${user.id}` },
    });
    return json({ uploadURL: direct.uploadURL, videoUid: direct.uid });
  }

  if (path === "/api/dj-verification" && method === "POST") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    if (!user.is_dj) return err("Only DJ accounts submit verification.", 403);
    const body = await request.json();
    const equipment = (body.equipment || "").trim();
    const platform = (body.platform || "").trim();
    const experience = (body.experience || "").trim();
    const videoUid = (body.videoUid || "").trim();
    if (!equipment || !platform || !videoUid) {
      return err("Tell us your equipment and platform, and upload a short video, to submit for verification.");
    }
    const id = genId("djv");
    await env.DB.prepare(`INSERT INTO dj_verifications (id, user_id, equipment, platform, experience, video_uid, status) VALUES (?,?,?,?,?,?, 'pending')`)
      .bind(id, user.id, equipment.slice(0, 500), platform.slice(0, 200), experience.slice(0, 1000), videoUid)
      .run();
    await env.DB.prepare(`UPDATE users SET dj_verification_status='pending' WHERE id=?`).bind(user.id).run();
    const row = await env.DB.prepare(`SELECT * FROM dj_verifications WHERE id=?`).bind(id).first();
    return json({ verification: publicVerification(row) });
  }

  if (path === "/api/dj-verification/mine" && method === "GET") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    const row = await env.DB.prepare(`SELECT * FROM dj_verifications WHERE user_id=? ORDER BY created_at DESC LIMIT 1`).bind(user.id).first();
    return json({ status: user.dj_verification_status || "unverified", verification: row ? publicVerification(row) : null });
  }

  // Admin (DJ verification review) --------------------------------------------
  if (path === "/api/admin/dj-verifications" && method === "GET") {
    const user = await getUserFromRequest(request, env);
    if (!user || !isAdminEmail(env, user.email)) return err("Forbidden.", 403);
    const status = url.searchParams.get("status") || "pending";
    const { results } = await env.DB.prepare(`SELECT * FROM dj_verifications WHERE status=? ORDER BY created_at ASC LIMIT 100`).bind(status).all();
    const out = [];
    for (const row of results) {
      const applicant = await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(row.user_id).first();
      out.push({ ...publicVerification(row), videoUrl: cfPlayerUrl(env, row.video_uid), applicant: publicUser(applicant) });
    }
    return json({ verifications: out });
  }

  if (path.match(/^\/api\/admin\/dj-verifications\/[^/]+\/approve$/) && method === "POST") {
    const verId = path.split("/")[4];
    const user = await getUserFromRequest(request, env);
    if (!user || !isAdminEmail(env, user.email)) return err("Forbidden.", 403);
    const row = await env.DB.prepare(`SELECT * FROM dj_verifications WHERE id=?`).bind(verId).first();
    if (!row) return err("Verification not found.", 404);
    await env.DB.prepare(`UPDATE dj_verifications SET status='approved', reviewed_by=?, reviewed_at=datetime('now') WHERE id=?`).bind(user.id, verId).run();
    await env.DB.prepare(`UPDATE users SET dj_verification_status='approved' WHERE id=?`).bind(row.user_id).run();
    return json({ ok: true });
  }

  if (path.match(/^\/api\/admin\/dj-verifications\/[^/]+\/reject$/) && method === "POST") {
    const verId = path.split("/")[4];
    const user = await getUserFromRequest(request, env);
    if (!user || !isAdminEmail(env, user.email)) return err("Forbidden.", 403);
    const body = await request.json().catch(() => ({}));
    const row = await env.DB.prepare(`SELECT * FROM dj_verifications WHERE id=?`).bind(verId).first();
    if (!row) return err("Verification not found.", 404);
    await env.DB.prepare(`UPDATE dj_verifications SET status='rejected', reviewer_note=?, reviewed_by=?, reviewed_at=datetime('now') WHERE id=?`)
      .bind((body.note || "").slice(0, 500), user.id, verId)
      .run();
    await env.DB.prepare(`UPDATE users SET dj_verification_status='rejected' WHERE id=?`).bind(row.user_id).run();
    return json({ ok: true });
  }

  // Tips / donations ---------------------------------------------------------
  if (path === "/api/tips" && method === "GET") {
    const djIdParam = url.searchParams.get("djId");
    let djId = djIdParam;
    if (!djIdParam || djIdParam === "me") {
      // "me" (or no djId at all) needs a real signed-in user to resolve —
      // an explicit djId is a public read (paid tips for a set are already
      // announced live in that stream's chat to every viewer, signed in or
      // not, so this isn't exposing anything new).
      const user = await getUserFromRequest(request, env);
      if (!user) return err("Sign in required.", 401);
      djId = user.id;
    }
    const { results } = await env.DB.prepare(`SELECT * FROM tips WHERE to_dj_id=? AND status='paid' ORDER BY created_at DESC LIMIT 200`).bind(djId).all();
    return json({ tips: results.map(publicTip) });
  }

  if (path === "/api/tips/checkout" && method === "POST") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required to send a tip.", 401);
    const body = await request.json();
    const amountCents = Math.round(Number(body.amount) * 100);
    if (!body.toDjId || !amountCents || amountCents < 100) return err("A valid tip amount (at least $1) and recipient are required.");
    const dj = await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(body.toDjId).first();
    if (!dj) return err("DJ not found.", 404);
    const origin = env.ALLOWED_ORIGIN || request.headers.get("Origin") || "https://example.com";
    const tipId = genId("tip");
    const session = await stripeRequest(env, "POST", "/checkout/sessions", {
      mode: "payment",
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: { name: `Tip: ${body.tierName || "Loop"} to ${dj.display_name}` },
            unit_amount: amountCents,
          },
          quantity: 1,
        },
      ],
      success_url: `${origin}/?tip_session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${origin}/?tip_cancelled=1`,
      metadata: { tipId, toDjId: body.toDjId, fromUserId: user.id, streamId: body.streamId || "", tierName: body.tierName || "", message: (body.message || "").slice(0, 120) },
    });
    await env.DB.prepare(`INSERT INTO tips (id, stripe_session_id, from_user_id, to_dj_id, stream_id, amount_cents, tier_name, message, status) VALUES (?,?,?,?,?,?,?,?, 'pending')`)
      .bind(tipId, session.id, user.id, body.toDjId, body.streamId || null, amountCents, body.tierName || null, body.message || null)
      .run();
    return json({ url: session.url });
  }

  if (path === "/api/tips/status" && method === "GET") {
    const sessionId = url.searchParams.get("session_id");
    if (!sessionId) return err("session_id is required.");
    let tip = await env.DB.prepare(`SELECT * FROM tips WHERE stripe_session_id=?`).bind(sessionId).first();
    if (!tip) return err("Tip not found.", 404);
    if (tip.status !== "paid") {
      try {
        const s = await stripeRequest(env, "GET", `/checkout/sessions/${sessionId}`);
        if (s.payment_status === "paid") {
          await markTipPaid(env, tip);
          tip = await env.DB.prepare(`SELECT * FROM tips WHERE id=?`).bind(tip.id).first();
        }
      } catch (e) {}
    }
    const dj = await env.DB.prepare(`SELECT display_name FROM users WHERE id=?`).bind(tip.to_dj_id).first();
    const fromUser = tip.from_user_id ? await env.DB.prepare(`SELECT display_name FROM users WHERE id=?`).bind(tip.from_user_id).first() : null;
    return json({
      paid: tip.status === "paid",
      tip: {
        id: tip.id,
        amount: tip.amount_cents / 100,
        tierName: tip.tier_name,
        message: tip.message,
        streamId: tip.stream_id,
        toDjId: tip.to_dj_id,
        djName: dj?.display_name,
        fromName: fromUser?.display_name || "Someone",
      },
    });
  }

  if (path === "/webhooks/stripe" && method === "POST") {
    const sig = request.headers.get("Stripe-Signature") || "";
    const bodyText = await request.text();
    const ok = env.STRIPE_WEBHOOK_SECRET ? await verifyStripeSignature(bodyText, sig, env.STRIPE_WEBHOOK_SECRET) : false;
    if (!ok) return err("Invalid signature.", 400);
    const event = JSON.parse(bodyText);
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const tip = await env.DB.prepare(`SELECT * FROM tips WHERE stripe_session_id=?`).bind(session.id).first();
      if (tip) await markTipPaid(env, tip);
    }
    return json({ received: true });
  }

  return err("Not found.", 404);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) });
    }
    try {
      const resp = await handle(request, env);
      if (resp.webSocket) return resp; // never rewrap a WebSocket upgrade
      const headers = new Headers(resp.headers);
      const cors = corsHeaders(env, request);
      for (const [k, v] of Object.entries(cors)) headers.set(k, v);
      return new Response(resp.body, { status: resp.status, headers });
    } catch (e) {
      return json({ error: e.message || "Server error." }, 500, corsHeaders(env, request));
    }
  },
};
