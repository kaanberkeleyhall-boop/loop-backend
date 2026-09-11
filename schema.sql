-- Loop backend schema (Cloudflare D1)
-- Run once with: wrangler d1 execute loop_db --remote --file=./schema.sql

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  city TEXT DEFAULT '',
  bio TEXT DEFAULT '',
  is_dj INTEGER NOT NULL DEFAULT 0,
  genres TEXT DEFAULT '[]',
  bpm_min INTEGER DEFAULT 118,
  bpm_max INTEGER DEFAULT 126,
  follower_count INTEGER NOT NULL DEFAULT 0,
  media_access_enabled INTEGER NOT NULL DEFAULT 1,
  two_factor_enabled INTEGER NOT NULL DEFAULT 0,
  -- unverified | pending | approved | rejected — only DJ accounts move past
  -- 'unverified'; going live requires 'approved' (see /api/streams).
  dj_verification_status TEXT NOT NULL DEFAULT 'unverified',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS auth_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_user ON auth_tokens(user_id);

CREATE TABLE IF NOT EXISTS streams (
  id TEXT PRIMARY KEY,
  dj_id TEXT NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  genres TEXT DEFAULT '[]',
  bpm_min INTEGER,
  bpm_max INTEGER,
  is_private INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'scheduled', -- scheduled | live | ended
  city TEXT DEFAULT '',
  start_time TEXT,
  end_time TEXT,
  live_input_uid TEXT,
  playback_uid TEXT,
  whip_url TEXT,
  rtmps_url TEXT,
  stream_key TEXT,
  peak_viewer_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_streams_dj ON streams(dj_id);
CREATE INDEX IF NOT EXISTS idx_streams_status ON streams(status);

CREATE TABLE IF NOT EXISTS follows (
  follower_id TEXT NOT NULL REFERENCES users(id),
  dj_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (follower_id, dj_id)
);

CREATE TABLE IF NOT EXISTS tips (
  id TEXT PRIMARY KEY,
  stripe_session_id TEXT UNIQUE,
  from_user_id TEXT REFERENCES users(id),
  to_dj_id TEXT NOT NULL REFERENCES users(id),
  stream_id TEXT REFERENCES streams(id),
  amount_cents INTEGER NOT NULL,
  tier_name TEXT,
  message TEXT,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | paid | failed
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  paid_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_tips_to_dj ON tips(to_dj_id);
CREATE INDEX IF NOT EXISTS idx_tips_stream ON tips(stream_id);

-- One row per DJ verification attempt. A DJ can resubmit after a rejection
-- (a new row each time), so review history isn't lost. users.dj_verification_status
-- always mirrors the latest row's status for that user.
CREATE TABLE IF NOT EXISTS dj_verifications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  equipment TEXT NOT NULL,
  platform TEXT NOT NULL,
  experience TEXT DEFAULT '',
  video_uid TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
  reviewer_note TEXT DEFAULT '',
  reviewed_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_dj_verifications_user ON dj_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_dj_verifications_status ON dj_verifications(status);

CREATE TABLE IF NOT EXISTS track_requests (
  id TEXT PRIMARY KEY,
  stream_id TEXT NOT NULL REFERENCES streams(id),
  requested_by_user_id TEXT NOT NULL REFERENCES users(id),
  query TEXT NOT NULL,
  amount_pledged_cents INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | queued | played | declined
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_requests_stream ON track_requests(stream_id);
