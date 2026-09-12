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
// Loop's cut of every tip. The remainder routes automatically to the DJ's
// own connected Stripe account the instant a tip is paid (see the
// payment_intent_data on /api/tips/checkout below) — only once that DJ has
// finished Stripe's own onboarding (see /api/connect/onboard).
const PLATFORM_FEE_PERCENT = 10;

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
    avatarUrl: row.avatar_data_url || "",
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

// ── security: brute-force / spam-signup throttling ───────────────────────
// A real, server-enforced limit (not just a UI hint) — checked against D1
// so it holds up across Worker restarts and multiple edge locations, unlike
// an in-memory counter. Old rows are cheap to leave behind; each check only
// looks inside its own recent window.
const RATE_LIMITS = {
  login: { max: 8, windowMinutes: 15 },
  signup: { max: 6, windowMinutes: 60 },
  password_reset: { max: 5, windowMinutes: 60 },
  verify_resend: { max: 3, windowMinutes: 30 },
};
function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
}
async function checkRateLimit(env, kind, key) {
  const cfg = RATE_LIMITS[kind];
  const since = new Date(Date.now() - cfg.windowMinutes * 60000).toISOString();
  const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM rate_limit_events WHERE kind=? AND rkey=? AND created_at > ?`)
    .bind(kind, key, since)
    .first();
  return (row?.n || 0) < cfg.max;
}
async function recordRateLimitEvent(env, kind, key) {
  await env.DB.prepare(`INSERT INTO rate_limit_events (kind, rkey) VALUES (?,?)`).bind(kind, key).run();
}

// ── email — password reset, email verification, "DJ went live" notices ────
// Sent through Resend's HTTP API (a real free tier, no credit card needed
// for the volume a small platform sends) — configured entirely via two
// Worker secrets (RESEND_API_KEY, RESEND_FROM_EMAIL), never hardcoded here.
// Best-effort everywhere it's called: a failed send never blocks or fails
// the request that triggered it (signup still succeeds even if the
// verification email doesn't go out, etc.) — it's logged and swallowed.
async function sendEmail(env, to, subject, html) {
  if (!env.RESEND_API_KEY || !env.RESEND_FROM_EMAIL) {
    console.log("Email not sent (RESEND_API_KEY/RESEND_FROM_EMAIL not configured):", subject, "→", to);
    return false;
  }
  try {
    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: env.RESEND_FROM_EMAIL, to, subject, html }),
    });
    if (!resp.ok) {
      console.log("Resend send failed:", resp.status, await resp.text().catch(() => ""));
      return false;
    }
    return true;
  } catch (e) {
    console.log("Resend send threw:", e.message);
    return false;
  }
}
function appUrl(env) {
  return (env.ALLOWED_ORIGIN && env.ALLOWED_ORIGIN !== "*" ? env.ALLOWED_ORIGIN : "").replace(/\/$/, "");
}
function emailShell(title, bodyHtml) {
  return `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#2c1c14;">
    <h2 style="margin:0 0 16px;">${title}</h2>
    ${bodyHtml}
    <p style="margin-top:32px;font-size:12px;color:#8a7a6f;">— Loop</p>
  </div>`;
}
async function createVerificationToken(env, userId, purpose, ttlMinutes) {
  const token = genToken();
  const expires = new Date(Date.now() + ttlMinutes * 60000).toISOString();
  await env.DB.prepare(`INSERT INTO verification_tokens (token, user_id, purpose, expires_at) VALUES (?,?,?,?)`).bind(token, userId, purpose, expires).run();
  return token;
}
async function consumeVerificationToken(env, token, purpose) {
  const row = await env.DB.prepare(`SELECT * FROM verification_tokens WHERE token=? AND purpose=? AND used_at IS NULL AND expires_at > datetime('now')`).bind(token, purpose).first();
  if (!row) return null;
  await env.DB.prepare(`UPDATE verification_tokens SET used_at=datetime('now') WHERE token=?`).bind(token).run();
  return row;
}
async function sendVerificationEmail(env, user) {
  const token = await createVerificationToken(env, user.id, "email_verify", 60 * 24);
  const link = `${appUrl(env)}/?verify=${token}`;
  await sendEmail(env, user.email, "Verify your Loop account",
    emailShell("Verify your email", `<p>Hi ${user.display_name || ""}, confirm this is your email address to finish setting up your Loop account.</p><p><a href="${link}" style="display:inline-block;background:#2f5b41;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none;">Verify email</a></p><p style="font-size:12px;color:#8a7a6f;">Or paste this link: ${link}</p>`)
  );
}
async function notifyFollowersLive(env, djId, streamTitle) {
  try {
    const dj = await env.DB.prepare(`SELECT display_name, username FROM users WHERE id=?`).bind(djId).first();
    if (!dj) return;
    const { results } = await env.DB.prepare(
      `SELECT u.email, u.display_name FROM follows f JOIN users u ON u.id = f.follower_id WHERE f.dj_id=? AND u.notify_on_live=1 AND u.email_verified=1 LIMIT 200`
    ).bind(djId).all();
    const link = `${appUrl(env)}/`;
    for (const follower of results) {
      await sendEmail(env, follower.email, `${dj.display_name} is live now on Loop`,
        emailShell(`${dj.display_name} just went live`, `<p>"${streamTitle}" is streaming right now.</p><p><a href="${link}" style="display:inline-block;background:#2f5b41;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none;">Watch now</a></p>`)
      );
    }
  } catch (e) {
    console.log("notifyFollowersLive failed:", e.message);
  }
}

// ── security: moderators & chat bans ─────────────────────────────────────
async function isModeratorFor(env, djId, userId) {
  if (!userId) return false;
  const row = await env.DB.prepare(`SELECT 1 FROM moderators WHERE dj_id=? AND moderator_id=?`).bind(djId, userId).first();
  return !!row;
}
async function chatRoleFor(env, djId, userId) {
  if (userId && userId === djId) return "dj";
  if (await isModeratorFor(env, djId, userId)) return "moderator";
  return "viewer";
}
function publicModerator(row) {
  return { userId: row.id, username: row.username, displayName: row.display_name, grantedAt: row.created_at };
}
function privateUser(row, env) {
  return {
    ...publicUser(row),
    email: row.email,
    mediaAccessEnabled: !!row.media_access_enabled,
    twoFactorEnabled: !!row.two_factor_enabled,
    verificationStatus: row.dj_verification_status || "unverified",
    isAdmin: env ? isAdminEmail(env, row.email) : false,
    emailVerified: !!row.email_verified,
    notifyOnLive: row.notify_on_live == null ? true : !!row.notify_on_live,
    // none = never started · pending = started but Stripe hasn't cleared
    // them to receive payouts yet · active = tips now split to them automatically.
    stripeConnectStatus: row.stripe_connect_account_id ? (row.stripe_connect_payouts_enabled ? "active" : "pending") : "none",
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
async function goLiveInternal(env, streamRow, ctx) {
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
  // Best-effort, never blocks the response the DJ is waiting on — a DJ going
  // live shouldn't stall because of an email provider hiccup.
  if (ctx) ctx.waitUntil(notifyFollowersLive(env, row.dj_id, row.title).catch(() => {}));
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
async function handle(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (path === "/" ) return json({ ok: true, service: "loop-api" });

  // Auth ---------------------------------------------------------------
  if (path === "/api/signup" && method === "POST") {
    const ip = clientIp(request);
    if (!(await checkRateLimit(env, "signup", ip))) return err("Too many accounts created from this connection recently. Please try again later.", 429);
    const body = await request.json();
    const email = (body.email || "").trim().toLowerCase();
    const displayName = (body.displayName || "").trim();
    const password = body.password || "";
    if (!email || !displayName || password.length < 6) return err("A display name, valid email, and a password of 6+ characters are required.");
    await recordRateLimitEvent(env, "signup", ip);
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
    ctx.waitUntil(sendVerificationEmail(env, user).catch(() => {}));
    return json({ token, user: privateUser(user, env) });
  }

  if (path === "/api/verify-email" && method === "POST") {
    const body = await request.json();
    const row = await consumeVerificationToken(env, body.token || "", "email_verify");
    if (!row) return err("This verification link is invalid or has expired.", 400);
    await env.DB.prepare(`UPDATE users SET email_verified=1 WHERE id=?`).bind(row.user_id).run();
    return json({ ok: true });
  }

  if (path === "/api/resend-verification" && method === "POST") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Not signed in.", 401);
    if (user.email_verified) return json({ ok: true, alreadyVerified: true });
    if (!(await checkRateLimit(env, "verify_resend", user.id))) return err("Please wait a bit before requesting another verification email.", 429);
    await recordRateLimitEvent(env, "verify_resend", user.id);
    await sendVerificationEmail(env, user);
    return json({ ok: true });
  }

  if (path === "/api/password-reset/request" && method === "POST") {
    const body = await request.json();
    const email = (body.email || "").trim().toLowerCase();
    // Always the same response whether or not the email exists — never lets
    // this endpoint be used to check which emails have Loop accounts.
    if (email && (await checkRateLimit(env, "password_reset", email))) {
      await recordRateLimitEvent(env, "password_reset", email);
      const user = await env.DB.prepare(`SELECT * FROM users WHERE email=?`).bind(email).first();
      if (user) {
        const token = await createVerificationToken(env, user.id, "password_reset", 60);
        const link = `${appUrl(env)}/?reset=${token}`;
        ctx.waitUntil(
          sendEmail(env, user.email, "Reset your Loop password",
            emailShell("Reset your password", `<p>Someone requested a password reset for this account. If that was you, set a new password:</p><p><a href="${link}" style="display:inline-block;background:#2f5b41;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none;">Reset password</a></p><p style="font-size:12px;color:#8a7a6f;">This link expires in 1 hour. If you didn't request this, you can ignore this email.</p>`)
          ).catch(() => {})
        );
      }
    }
    return json({ ok: true });
  }

  if (path === "/api/password-reset/confirm" && method === "POST") {
    const body = await request.json();
    const newPassword = body.newPassword || "";
    if (newPassword.length < 6) return err("Password must be at least 6 characters.");
    const row = await consumeVerificationToken(env, body.token || "", "password_reset");
    if (!row) return err("This reset link is invalid or has expired.", 400);
    const { hashHex, saltHex } = await pbkdf2Hash(newPassword);
    await env.DB.prepare(`UPDATE users SET password_hash=?, password_salt=? WHERE id=?`).bind(hashHex, saltHex, row.user_id).run();
    // Force re-login everywhere — a reset should invalidate any session that
    // might belong to whoever no longer has the (possibly compromised) old password.
    await env.DB.prepare(`DELETE FROM auth_tokens WHERE user_id=?`).bind(row.user_id).run();
    return json({ ok: true });
  }

  if (path === "/api/login" && method === "POST") {
    const body = await request.json();
    const email = (body.email || "").trim().toLowerCase();
    const password = body.password || "";
    if (!(await checkRateLimit(env, "login", email))) {
      return err("Too many failed sign-in attempts for this account. Please wait 15 minutes and try again.", 429);
    }
    const user = await env.DB.prepare(`SELECT * FROM users WHERE email=?`).bind(email).first();
    if (!user) {
      await recordRateLimitEvent(env, "login", email);
      return err("Incorrect email or password.", 401);
    }
    const { hashHex } = await pbkdf2Hash(password, user.password_salt);
    if (hashHex !== user.password_hash) {
      await recordRateLimitEvent(env, "login", email);
      return err("Incorrect email or password.", 401);
    }
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
    if (body.notifyOnLive !== undefined) set("notify_on_live", body.notifyOnLive ? 1 : 0);
    if (body.avatarUrl !== undefined) {
      // Stored directly in D1 as a data: URL — no separate image/CDN product,
      // so this stays tightly capped: only a data:image/... value, and small
      // enough that a resized (client-side, before upload) photo always fits
      // comfortably well under it.
      if (body.avatarUrl === "") {
        set("avatar_data_url", "");
      } else if (typeof body.avatarUrl === "string" && /^data:image\/(png|jpeg|jpg|webp);base64,/.test(body.avatarUrl) && body.avatarUrl.length <= 400000) {
        set("avatar_data_url", body.avatarUrl);
      } else {
        return err("Profile photo is invalid or too large.", 400);
      }
    }
    if (fields.length) {
      binds.push(user.id);
      await env.DB.prepare(`UPDATE users SET ${fields.join(", ")} WHERE id=?`).bind(...binds).run();
    }
    const updated = await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(user.id).first();
    return json({ user: privateUser(updated, env) });
  }

  if (path === "/api/users" && method === "GET") {
    const isDj = url.searchParams.get("isDj");
    const search = (url.searchParams.get("q") || "").trim();
    const sort = url.searchParams.get("sort") || "followers"; // followers | newest
    let q = "SELECT * FROM users";
    const clauses = [];
    const binds = [];
    if (isDj) clauses.push("is_dj=1");
    if (search) {
      clauses.push("(display_name LIKE ? OR username LIKE ? OR city LIKE ? OR genres LIKE ?)");
      const like = `%${search}%`;
      binds.push(like, like, like, like);
    }
    if (clauses.length) q += " WHERE " + clauses.join(" AND ");
    q += sort === "newest" ? " ORDER BY created_at DESC LIMIT 100" : " ORDER BY follower_count DESC LIMIT 100";
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
      stream = await goLiveInternal(env, row, ctx);
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
    const stream = await goLiveInternal(env, row, ctx);
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
    const stream = await env.DB.prepare(`SELECT id, dj_id FROM streams WHERE id=?`).bind(streamId).first();
    if (!stream) return err("Stream not found.", 404);
    // A banned user can watch (viewer counts stay real for everyone) but
    // can't rejoin that DJ's chat — enforced here, not just hidden in the UI.
    if (row) {
      const banned = await env.DB.prepare(`SELECT 1 FROM chat_bans WHERE dj_id=? AND banned_user_id=?`).bind(stream.dj_id, row.id).first();
      if (banned) return err("You've been removed from this DJ's chat.", 403);
    }
    const role = row ? await chatRoleFor(env, stream.dj_id, row.id) : "viewer";
    const id = env.CHAT_ROOM.idFromName(streamId);
    const stub = env.CHAT_ROOM.get(id);
    const doUrl = new URL(request.url);
    doUrl.pathname = "/room";
    doUrl.searchParams.set("userId", row ? row.id : "");
    doUrl.searchParams.set("displayName", row ? row.display_name : "Guest");
    doUrl.searchParams.set("role", role);
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

  // Moderators — a DJ's chosen chat moderators -------------------------------
  if (path === "/api/moderators" && method === "GET") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    const { results } = await env.DB.prepare(
      `SELECT u.* FROM moderators m JOIN users u ON u.id = m.moderator_id WHERE m.dj_id=? ORDER BY m.created_at ASC`
    )
      .bind(user.id)
      .all();
    return json({ moderators: results.map(publicModerator) });
  }
  if (path === "/api/moderators" && method === "POST") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    if (!user.is_dj) return err("Only DJ accounts can appoint moderators.", 403);
    const body = await request.json();
    const handle = (body.username || "").trim().toLowerCase();
    if (!handle) return err("Enter a username to add as a moderator.");
    const target = await env.DB.prepare(`SELECT * FROM users WHERE username=? OR email=?`).bind(handle, handle).first();
    if (!target) return err("No account found with that username.", 404);
    if (target.id === user.id) return err("You can't appoint yourself.");
    await env.DB.prepare(`INSERT OR IGNORE INTO moderators (dj_id, moderator_id) VALUES (?,?)`).bind(user.id, target.id).run();
    return json({ moderator: publicModerator(target) });
  }
  if (path.match(/^\/api\/moderators\/[^/]+$/) && method === "DELETE") {
    const modUserId = path.split("/")[3];
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    await env.DB.prepare(`DELETE FROM moderators WHERE dj_id=? AND moderator_id=?`).bind(user.id, modUserId).run();
    return json({ ok: true });
  }
  // Which DJs the signed-in user moderates for — lets the frontend show
  // moderation controls in the right chats without the DJ having to do
  // anything special for that viewer.
  if (path === "/api/moderators/mine" && method === "GET") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    const { results } = await env.DB.prepare(`SELECT dj_id FROM moderators WHERE moderator_id=?`).bind(user.id).all();
    return json({ djIds: results.map((r) => r.dj_id) });
  }

  // Chat bans — enforced both here (join-time) and live in the ChatRoom ------
  if (path.match(/^\/api\/streams\/[^/]+\/chat\/ban$/) && method === "POST") {
    const streamId = path.split("/")[3];
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    const stream = await env.DB.prepare(`SELECT * FROM streams WHERE id=?`).bind(streamId).first();
    if (!stream) return err("Stream not found.", 404);
    const role = await chatRoleFor(env, stream.dj_id, user.id);
    if (role === "viewer") return err("Only the DJ or one of their moderators can do that.", 403);
    const body = await request.json();
    if (!body.userId) return err("A userId is required.");
    if (body.userId === stream.dj_id) return err("You can't ban the DJ.");
    await env.DB.prepare(`INSERT OR REPLACE INTO chat_bans (dj_id, banned_user_id, banned_by, reason) VALUES (?,?,?,?)`)
      .bind(stream.dj_id, body.userId, user.id, (body.reason || "").slice(0, 300))
      .run();
    try {
      const id = env.CHAT_ROOM.idFromName(streamId);
      const stub = env.CHAT_ROOM.get(id);
      await stub.fetch("https://do/kick", { method: "POST", body: JSON.stringify({ userId: body.userId, reason: "banned" }) });
    } catch (e) {}
    return json({ ok: true });
  }
  if (path.match(/^\/api\/streams\/[^/]+\/chat\/unban$/) && method === "POST") {
    const streamId = path.split("/")[3];
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    const stream = await env.DB.prepare(`SELECT * FROM streams WHERE id=?`).bind(streamId).first();
    if (!stream) return err("Stream not found.", 404);
    const role = await chatRoleFor(env, stream.dj_id, user.id);
    if (role === "viewer") return err("Only the DJ or one of their moderators can do that.", 403);
    const body = await request.json();
    await env.DB.prepare(`DELETE FROM chat_bans WHERE dj_id=? AND banned_user_id=?`).bind(stream.dj_id, body.userId).run();
    return json({ ok: true });
  }
  if (path.match(/^\/api\/streams\/[^/]+\/chat\/bans$/) && method === "GET") {
    const streamId = path.split("/")[3];
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    const stream = await env.DB.prepare(`SELECT * FROM streams WHERE id=?`).bind(streamId).first();
    if (!stream) return err("Stream not found.", 404);
    const role = await chatRoleFor(env, stream.dj_id, user.id);
    if (role === "viewer") return err("Only the DJ or one of their moderators can do that.", 403);
    const { results } = await env.DB.prepare(
      `SELECT u.id, u.username, u.display_name, b.reason, b.created_at FROM chat_bans b JOIN users u ON u.id = b.banned_user_id WHERE b.dj_id=? ORDER BY b.created_at DESC`
    )
      .bind(stream.dj_id)
      .all();
    return json({ bans: results.map((r) => ({ userId: r.id, username: r.username, displayName: r.display_name, reason: r.reason, bannedAt: r.created_at })) });
  }

  // Reports — any signed-in user can flag a message or a user ---------------
  if (path === "/api/reports" && method === "POST") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    const body = await request.json();
    if (!body.reason) return err("A reason is required.");
    const id = genId("report");
    await env.DB.prepare(
      `INSERT INTO reports (id, reporter_id, reported_user_id, stream_id, message_text, reason, details) VALUES (?,?,?,?,?,?,?)`
    )
      .bind(id, user.id, body.reportedUserId || null, body.streamId || null, (body.messageText || "").slice(0, 300), body.reason.slice(0, 100), (body.details || "").slice(0, 1000))
      .run();
    return json({ ok: true });
  }
  if (path === "/api/admin/reports" && method === "GET") {
    const user = await getUserFromRequest(request, env);
    if (!user || !isAdminEmail(env, user.email)) return err("Forbidden.", 403);
    const status = url.searchParams.get("status") || "open";
    const { results } = await env.DB.prepare(`SELECT * FROM reports WHERE status=? ORDER BY created_at ASC LIMIT 200`).bind(status).all();
    const out = [];
    for (const row of results) {
      const reporter = await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(row.reporter_id).first();
      const reported = row.reported_user_id ? await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(row.reported_user_id).first() : null;
      out.push({
        id: row.id,
        reason: row.reason,
        details: row.details || "",
        messageText: row.message_text || "",
        streamId: row.stream_id,
        status: row.status,
        createdAt: row.created_at,
        reporter: publicUser(reporter),
        reportedUser: reported ? publicUser(reported) : null,
      });
    }
    return json({ reports: out });
  }
  if (path.match(/^\/api\/admin\/reports\/[^/]+\/(resolve|dismiss)$/) && method === "POST") {
    const parts = path.split("/");
    const reportId = parts[4];
    const action = parts[5];
    const user = await getUserFromRequest(request, env);
    if (!user || !isAdminEmail(env, user.email)) return err("Forbidden.", 403);
    await env.DB.prepare(`UPDATE reports SET status=?, reviewed_by=?, reviewed_at=datetime('now') WHERE id=?`)
      .bind(action === "resolve" ? "resolved" : "dismissed", user.id, reportId)
      .run();
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
    const sessionParams = {
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
    };
    // Split the payment at the moment it's paid: Loop's cut stays in the
    // platform balance, the rest transfers straight to the DJ's own
    // connected Stripe account — but only once that account is actually
    // cleared to receive payouts. Until then (or if they've never
    // connected one), the whole tip lands in the platform balance instead,
    // same as before.
    if (dj.stripe_connect_account_id && dj.stripe_connect_payouts_enabled) {
      sessionParams.payment_intent_data = {
        application_fee_amount: Math.round((amountCents * PLATFORM_FEE_PERCENT) / 100),
        transfer_data: { destination: dj.stripe_connect_account_id },
      };
    }
    const session = await stripeRequest(env, "POST", "/checkout/sessions", sessionParams);
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

  // Payouts (Stripe Connect) ---------------------------------------------
  // Lets a DJ link their own bank account so their share of every tip
  // routes to them automatically the instant it's paid (see
  // PLATFORM_FEE_PERCENT and /api/tips/checkout above). Stripe hosts the
  // actual "enter your bank details / verify your identity" flow — this
  // server only creates the connected account, asks Stripe for a link to
  // that hosted flow, and later re-checks whether the account is cleared.
  if (path === "/api/connect/onboard" && method === "POST") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    if (!user.is_dj) return err("Only DJ accounts can connect a payout method.", 403);
    const origin = env.ALLOWED_ORIGIN || request.headers.get("Origin") || "https://example.com";
    let accountId = user.stripe_connect_account_id;
    if (!accountId) {
      const acct = await stripeRequest(env, "POST", "/accounts", {
        type: "express",
        email: user.email,
        business_type: "individual",
        capabilities: { transfers: { requested: true } },
      });
      accountId = acct.id;
      await env.DB.prepare(`UPDATE users SET stripe_connect_account_id=? WHERE id=?`).bind(accountId, user.id).run();
    }
    const link = await stripeRequest(env, "POST", "/account_links", {
      account: accountId,
      refresh_url: `${origin}/?connect_refresh=1`,
      return_url: `${origin}/?connect_return=1`,
      type: "account_onboarding",
    });
    return json({ url: link.url });
  }

  if (path === "/api/connect/refresh" && method === "POST") {
    const user = await getUserFromRequest(request, env);
    if (!user) return err("Sign in required.", 401);
    if (user.stripe_connect_account_id) {
      const acct = await stripeRequest(env, "GET", `/accounts/${user.stripe_connect_account_id}`);
      const enabled = !!(acct.details_submitted && acct.payouts_enabled);
      await env.DB.prepare(`UPDATE users SET stripe_connect_payouts_enabled=? WHERE id=?`).bind(enabled ? 1 : 0, user.id).run();
    }
    const updated = await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(user.id).first();
    return json({ user: privateUser(updated, env) });
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
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) });
    }
    try {
      const resp = await handle(request, env, ctx);
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
