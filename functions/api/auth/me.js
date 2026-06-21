import { getCurrentUser, json } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const user = await getCurrentUser(request, env);
  return json({ user });
}
