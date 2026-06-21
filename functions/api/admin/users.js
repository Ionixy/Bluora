import { json, requireAdmin } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const auth = await requireAdmin(request, env);
  if (auth.error) return auth.error;

  const { results } = await env.DB
    .prepare('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC')
    .all();

  return json({ users: results });
}
