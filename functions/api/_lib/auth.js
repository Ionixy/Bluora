const SESSION_COOKIE = 'bluora_session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 14;

export function json(data, init = {}) {
  return Response.json(data, init);
}

function getCookie(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  return cookie
    .split(';')
    .map(part => part.trim())
    .find(part => part.startsWith(`${name}=`))
    ?.slice(name.length + 1) || '';
}

function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function sha256(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return bytesToBase64(new Uint8Array(digest));
}

export function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

export function validatePassword(password) {
  return typeof password === 'string' && password.length >= 8;
}

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    key,
    256
  );
  return `pbkdf2:${bytesToBase64(salt)}:${bytesToBase64(new Uint8Array(bits))}`;
}

export async function verifyPassword(password, passwordHash) {
  const [scheme, saltValue, expectedValue] = String(passwordHash || '').split(':');
  if (scheme !== 'pbkdf2' || !saltValue || !expectedValue) return false;

  const salt = base64ToBytes(saltValue);
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    key,
    256
  );
  return await sha256(bytesToBase64(new Uint8Array(bits))) === await sha256(expectedValue);
}

export function makeSessionCookie(sessionId, maxAge = SESSION_TTL_SECONDS) {
  return `${SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

export function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export async function createSession(env, userId) {
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;

  await env.DB
    .prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(sessionId, userId, expiresAt)
    .run();

  return sessionId;
}

export async function getCurrentUser(request, env) {
  const sessionId = getCookie(request, SESSION_COOKIE);
  if (!sessionId) return null;

  const row = await env.DB
    .prepare(`
      SELECT users.id, users.email, users.role, sessions.expires_at
      FROM sessions
      JOIN users ON users.id = sessions.user_id
      WHERE sessions.id = ?
      LIMIT 1
    `)
    .bind(sessionId)
    .first();

  if (!row) return null;
  if (Number(row.expires_at) < Date.now()) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionId).run();
    return null;
  }

  return { id: row.id, email: row.email, role: row.role };
}

export async function requireAdmin(request, env) {
  const user = await getCurrentUser(request, env);
  if (!user || user.role !== 'admin') {
    return { error: json({ error: 'Admin access required' }, { status: 401 }) };
  }
  return { user };
}

export async function destroySession(request, env) {
  const sessionId = getCookie(request, SESSION_COOKIE);
  if (sessionId) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionId).run();
  }
}
