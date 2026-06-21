-- Run this once in the Cloudflare D1 Console only when the users table already exists.
ALTER TABLE users ADD COLUMN username TEXT;
UPDATE users SET username = 'user-' || id WHERE username IS NULL OR username = '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username COLLATE NOCASE);
