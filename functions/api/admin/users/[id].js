import { json, requireAdmin } from '../../../_lib/auth.js';

export async function onRequestPatch({ request, env, params }) {
  const auth = await requireAdmin(request, env);
  if (auth.error) return auth.error;

  const id = Number(params.id);
  const { role } = await request.json();

  if (!Number.isInteger(id) || id < 1 || !['admin', 'user'].includes(role)) {
    return json({ error: 'Role must be admin or user.' }, { status: 400 });
  }

  const target = await env.DB.prepare('SELECT id, role FROM users WHERE id = ?').bind(id).first();
  if (!target) return json({ error: 'User not found.' }, { status: 404 });
  if (id === Number(auth.user.id) && role !== 'admin') {
    return json({ error: 'You cannot remove your own administrator access.' }, { status: 400 });
  }
  if (target.role === 'admin' && role === 'user') {
    const adminCount = await env.DB.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").first();
    if (Number(adminCount?.count || 0) <= 1) {
      return json({ error: 'At least one administrator must remain.' }, { status: 400 });
    }
  }

  await env.DB.prepare('UPDATE users SET role = ? WHERE id = ?').bind(role, id).run();
  return json({ success: true });
}
