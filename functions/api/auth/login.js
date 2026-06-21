import { createSession, json, makeSessionCookie, normalizeEmail, verifyPassword } from '../../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const { email, password } = await request.json();
  const normalizedEmail = normalizeEmail(email);

  let user;
  try {
    user = await env.DB
      .prepare('SELECT id, username, email, password_hash, role FROM users WHERE email = ? LIMIT 1')
      .bind(normalizedEmail)
      .first();
  } catch {
    user = await env.DB
      .prepare('SELECT id, email, password_hash, role FROM users WHERE email = ? LIMIT 1')
      .bind(normalizedEmail)
      .first();
  }

  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return json({ error: 'Invalid email or password.' }, { status: 401 });
  }

  const sessionId = await createSession(env, user.id);
  return json(
    { user: { id: user.id, username: user.username || user.email.split('@')[0].slice(0, 12), email: user.email, role: user.role, isPrimaryAdmin: normalizeEmail(user.email) === normalizeEmail(env.FIRST_ADMIN_EMAIL) } },
    { headers: { 'Set-Cookie': makeSessionCookie(sessionId) } }
  );
}
