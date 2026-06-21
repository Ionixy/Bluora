import { createSession, hashPassword, json, makeSessionCookie, normalizeEmail, normalizeUsername, validatePassword, validateUsername } from '../../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const { username, email, password } = await request.json();
  const normalizedEmail = normalizeEmail(email);
  const normalizedUsername = normalizeUsername(username);

  if (!validateUsername(normalizedUsername)) {
    return json({ error: 'Username must use 3-12 letters, numbers, hyphens, or underscores.' }, { status: 400 });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) || !validatePassword(password)) {
    return json({ error: 'Enter a valid email and a password of at least 8 characters.' }, { status: 400 });
  }

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(normalizedEmail).first();
  if (existing) {
    return json({ error: 'User already exists.' }, { status: 409 });
  }
  const existingUsername = await env.DB.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE').bind(normalizedUsername).first();
  if (existingUsername) return json({ error: 'This username is already taken.' }, { status: 409 });

  const adminCount = await env.DB.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").first();
  let role = 'user';

  if (Number(adminCount?.count || 0) === 0) {
    const bootstrapEmail = normalizeEmail(env.FIRST_ADMIN_EMAIL);
    if (!bootstrapEmail) {
      return json({ error: 'Initial setup is incomplete. Set FIRST_ADMIN_EMAIL in Cloudflare first.' }, { status: 503 });
    }
    if (normalizedEmail !== bootstrapEmail) {
      return json({ error: 'Register using the email configured for the first administrator.' }, { status: 403 });
    }
    role = 'admin';
  }
  const passwordHash = await hashPassword(password);

  const result = await env.DB
    .prepare('INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(normalizedUsername, normalizedEmail, passwordHash, role, Date.now())
    .run();

  const sessionId = await createSession(env, result.meta.last_row_id);
  return json(
    { user: { id: result.meta.last_row_id, username: normalizedUsername, email: normalizedEmail, role, isPrimaryAdmin: role === 'admin' } },
    { headers: { 'Set-Cookie': makeSessionCookie(sessionId) } }
  );
}
