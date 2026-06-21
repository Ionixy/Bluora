import { clearSessionCookie, destroySession, json } from '../../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  await destroySession(request, env);
  return json({ success: true }, { headers: { 'Set-Cookie': clearSessionCookie() } });
}
