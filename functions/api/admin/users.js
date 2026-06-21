import { json, requireAdmin } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const auth = await requireAdmin(request, env);
  if (auth.error) return auth.error;

  let results;
  try {
    ({ results } = await env.DB
      .prepare('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC')
      .all());
  } catch {
    ({ results } = await env.DB
      .prepare('SELECT id, email, role, created_at FROM users ORDER BY created_at DESC')
      .all());
  }

  return json({ users: results.map(user => ({ ...user, username: user.username || user.email.split('@')[0].slice(0, 12) })) });
}
