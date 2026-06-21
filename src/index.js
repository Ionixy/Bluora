const SESSION_COOKIE = "bluora_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 14;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/auth/register" && request.method === "POST") return register(request, env);
    if (url.pathname === "/api/auth/login" && request.method === "POST") return login(request, env);
    if (url.pathname === "/api/auth/logout" && request.method === "POST") return logout(request, env);
    if (url.pathname === "/api/auth/me" && request.method === "GET") return me(request, env);
    if (url.pathname === "/api/admin/users" && request.method === "GET") return listUsers(request, env);

    const adminUserMatch = url.pathname.match(/^\/api\/admin\/users\/(\d+)$/);
    if (adminUserMatch && request.method === "PATCH") return updateUserRole(request, env, Number(adminUserMatch[1]));
    if (adminUserMatch && request.method === "DELETE") return deleteUser(request, env, Number(adminUserMatch[1]));

    if (url.pathname === "/api/products" && request.method === "GET") return listProducts(env);
    if (url.pathname === "/api/products" && request.method === "POST") return createProduct(request, env);

    const productMatch = url.pathname.match(/^\/api\/products\/(\d+)$/);
    if (productMatch && request.method === "PUT") return updateProduct(request, env, Number(productMatch[1]));
    if (productMatch && request.method === "DELETE") return deleteProduct(request, env, Number(productMatch[1]));

    if (url.pathname === "/api/remove-bg" && request.method === "POST") return handleRemoveBg(request, env);

    return env.ASSETS.fetch(request);
  }
};

function json(data, init = {}) {
  return Response.json(data, init);
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  return cookie
    .split(";")
    .map(part => part.trim())
    .find(part => part.startsWith(`${name}=`))
    ?.slice(name.length + 1) || "";
}

function bytesToBase64(bytes) {
  let binary = "";
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
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64(new Uint8Array(digest));
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function validatePassword(password) {
  return typeof password === "string" && password.length >= 8;
}

function normalizeUsername(username) {
  return String(username || "").trim();
}

function validateUsername(username) {
  const value = normalizeUsername(username);
  return Array.from(value).length >= 3 && Array.from(value).length <= 12 && /^[\p{L}\p{N}_-]+$/u.test(value);
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  return `pbkdf2:${bytesToBase64(salt)}:${bytesToBase64(new Uint8Array(bits))}`;
}

async function verifyPassword(password, passwordHash) {
  const [scheme, saltValue, expectedValue] = String(passwordHash || "").split(":");
  if (scheme !== "pbkdf2" || !saltValue || !expectedValue) return false;

  const salt = base64ToBytes(saltValue);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  return await sha256(bytesToBase64(new Uint8Array(bits))) === await sha256(expectedValue);
}

function makeSessionCookie(sessionId, maxAge = SESSION_TTL_SECONDS) {
  return `${SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

async function createSession(env, userId) {
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;

  await env.DB
    .prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
    .bind(sessionId, userId, expiresAt)
    .run();

  return sessionId;
}

async function getCurrentUser(request, env) {
  const sessionId = getCookie(request, SESSION_COOKIE);
  if (!sessionId) return null;

  const row = await env.DB
    .prepare(`
      SELECT users.id, users.email, users.username, users.role, sessions.expires_at
      FROM sessions
      JOIN users ON users.id = sessions.user_id
      WHERE sessions.id = ?
      LIMIT 1
    `)
    .bind(sessionId)
    .first();

  if (!row) return null;
  if (Number(row.expires_at) < Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sessionId).run();
    return null;
  }

  return {
    id: row.id,
    email: row.email,
    username: row.username,
    role: row.role,
    isPrimaryAdmin: normalizeEmail(row.email) === normalizeEmail(env.FIRST_ADMIN_EMAIL)
  };
}

async function requireAdmin(request, env) {
  const user = await getCurrentUser(request, env);
  if (!user || user.role !== "admin") {
    return { error: json({ error: "Admin access required" }, { status: 401 }) };
  }
  return { user };
}

async function register(request, env) {
  const { username, email, password } = await request.json();
  const normalizedEmail = normalizeEmail(email);
  const normalizedUsername = normalizeUsername(username);

  if (!validateUsername(normalizedUsername)) {
    return json({ error: "Username must use 3-12 letters, numbers, hyphens, or underscores." }, { status: 400 });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) || !validatePassword(password)) {
    return json({ error: "Enter a valid email and a password of at least 8 characters." }, { status: 400 });
  }

  const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(normalizedEmail).first();
  if (existing) return json({ error: "User already exists." }, { status: 409 });
  const existingUsername = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(normalizedUsername).first();
  if (existingUsername) return json({ error: "This username is already taken." }, { status: 409 });

  const adminCount = await env.DB.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").first();
  let role = "user";

  if (Number(adminCount?.count || 0) === 0) {
    const bootstrapEmail = normalizeEmail(env.FIRST_ADMIN_EMAIL);
    if (!bootstrapEmail) {
      return json({ error: "Initial setup is incomplete. Set FIRST_ADMIN_EMAIL in Cloudflare first." }, { status: 503 });
    }
    if (normalizedEmail !== bootstrapEmail) {
      return json({ error: "Register using the email configured for the first administrator." }, { status: 403 });
    }
    role = "admin";
  }
  const result = await env.DB
    .prepare("INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(normalizedUsername, normalizedEmail, await hashPassword(password), role, Date.now())
    .run();

  const sessionId = await createSession(env, result.meta.last_row_id);
  return json(
    { user: { id: result.meta.last_row_id, username: normalizedUsername, email: normalizedEmail, role, isPrimaryAdmin: role === "admin" } },
    { headers: { "Set-Cookie": makeSessionCookie(sessionId) } }
  );
}

async function login(request, env) {
  const { email, password } = await request.json();
  const user = await env.DB
    .prepare("SELECT id, username, email, password_hash, role FROM users WHERE email = ? LIMIT 1")
    .bind(normalizeEmail(email))
    .first();

  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return json({ error: "Invalid email or password." }, { status: 401 });
  }

  const sessionId = await createSession(env, user.id);
  return json(
    { user: { id: user.id, username: user.username, email: user.email, role: user.role, isPrimaryAdmin: normalizeEmail(user.email) === normalizeEmail(env.FIRST_ADMIN_EMAIL) } },
    { headers: { "Set-Cookie": makeSessionCookie(sessionId) } }
  );
}

async function logout(request, env) {
  const sessionId = getCookie(request, SESSION_COOKIE);
  if (sessionId) await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sessionId).run();
  return json({ success: true }, { headers: { "Set-Cookie": clearSessionCookie() } });
}

async function me(request, env) {
  return json({ user: await getCurrentUser(request, env) });
}

async function listUsers(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth.error) return auth.error;

  const { results } = await env.DB
    .prepare("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC")
    .all();

  return json({ users: results });
}

async function updateUserRole(request, env, id) {
  const auth = await requireAdmin(request, env);
  if (auth.error) return auth.error;

  const { role } = await request.json();
  if (!Number.isInteger(Number(id)) || Number(id) < 1 || !["admin", "user"].includes(role)) {
    return json({ error: "Role must be admin or user." }, { status: 400 });
  }

  const target = await env.DB.prepare("SELECT id, role FROM users WHERE id = ?").bind(id).first();
  if (!target) return json({ error: "User not found." }, { status: 404 });
  if (Number(id) === Number(auth.user.id) && role !== "admin") {
    return json({ error: "You cannot remove your own administrator access." }, { status: 400 });
  }
  if (target.role === "admin" && role === "user") {
    const adminCount = await env.DB.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").first();
    if (Number(adminCount?.count || 0) <= 1) {
      return json({ error: "At least one administrator must remain." }, { status: 400 });
    }
  }

  await env.DB.prepare("UPDATE users SET role = ? WHERE id = ?").bind(role, id).run();
  return json({ success: true });
}

async function deleteUser(request, env, id) {
  const auth = await requireAdmin(request, env);
  if (auth.error) return auth.error;
  if (!auth.user.isPrimaryAdmin || normalizeEmail(auth.user.email) !== normalizeEmail(env.FIRST_ADMIN_EMAIL)) {
    return json({ error: "Only the primary administrator can delete accounts." }, { status: 403 });
  }
  if (!Number.isInteger(id) || id < 1) return json({ error: "Invalid user id." }, { status: 400 });
  if (id === Number(auth.user.id)) return json({ error: "You cannot delete your own account." }, { status: 400 });

  const target = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(id).first();
  if (!target) return json({ error: "User not found." }, { status: 404 });
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id),
    env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id)
  ]);
  return json({ success: true });
}

function parseProduct(row) {
  return {
    ...row,
    images: JSON.parse(row.images || "[]"),
    isNewDrop: Boolean(row.isNewDrop),
    newDropUntil: row.newDropUntil ?? null
  };
}

async function listProducts(env) {
  const { results } = await env.DB.prepare("SELECT * FROM products ORDER BY id DESC").all();
  return json(results.map(parseProduct));
}

async function createProduct(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth.error) return auth.error;

  const body = await request.json();
  if (!body.name || !body.category) return json({ error: "name and category are required" }, { status: 400 });

  const result = await env.DB
    .prepare(`
      INSERT INTO products (name, type, category, images, description, specs, isNewDrop, newDropUntil)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .bind(
      body.name,
      body.type || "Replica",
      body.category,
      JSON.stringify(body.images || []),
      body.description || "",
      body.specs || "",
      body.isNewDrop ? 1 : 0,
      body.newDropUntil || null
    )
    .run();

  return json({ success: true, id: result.meta.last_row_id });
}

async function updateProduct(request, env, id) {
  const auth = await requireAdmin(request, env);
  if (auth.error) return auth.error;

  const body = await request.json();
  await env.DB
    .prepare(`
      UPDATE products
      SET name = ?, type = ?, category = ?, images = ?, description = ?, specs = ?, isNewDrop = ?, newDropUntil = ?
      WHERE id = ?
    `)
    .bind(
      body.name,
      body.type || "Replica",
      body.category,
      JSON.stringify(body.images || []),
      body.description || "",
      body.specs || "",
      body.isNewDrop ? 1 : 0,
      body.newDropUntil || null,
      id
    )
    .run();

  return json({ success: true });
}

async function deleteProduct(request, env, id) {
  const auth = await requireAdmin(request, env);
  if (auth.error) return auth.error;

  await env.DB.prepare("DELETE FROM products WHERE id = ?").bind(id).run();
  return json({ success: true });
}

function getRemoveBgApiKey(env) {
  return env.REMOVEBG_API_KEY || env.REMOVE_BG_API_KEY || env.REMOVEBG_TOKEN || env.REMOVE_BG_TOKEN;
}

async function handleRemoveBg(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth.error) return auth.error;

  const apiKey = getRemoveBgApiKey(env);
  if (!apiKey) {
    return json({ error: "Remove.bg API key is missing. Add REMOVEBG_API_KEY in Cloudflare secrets." }, { status: 500 });
  }

  const { imageUrl } = await request.json();
  if (!imageUrl) return json({ error: "imageUrl is required" }, { status: 400 });

  const form = new FormData();
  form.append("image_url", imageUrl);
  form.append("size", "auto");
  form.append("format", "png");

  const response = await fetch("https://api.remove.bg/v1.0/removebg", {
    method: "POST",
    headers: { "X-Api-Key": apiKey },
    body: form
  });

  if (!response.ok) return json({ error: await response.text() }, { status: response.status });

  return new Response(await response.arrayBuffer(), {
    headers: { "Content-Type": "image/png" }
  });
}
