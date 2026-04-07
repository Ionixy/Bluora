function isAuthorized(request, env) {
  const token = request.headers.get('x-admin-token');
  return token === env.ADMIN_TOKEN;
}

export async function onRequestGet(context) {
  const { env } = context;

  const { results } = await env.DB
    .prepare("SELECT * FROM products ORDER BY id DESC")
    .all();

  const products = results.map((p) => ({
    ...p,
    images: JSON.parse(p.images || "[]"),
    isNewDrop: Boolean(p.isNewDrop),
    newDropUntil: p.newDropUntil ?? null,
  }));

  return Response.json(products);
}

export async function onRequestPost(context) {
  const { env, request } = context;

  if (!isAuthorized(request, env)) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const body = await request.json();

  const {
    name,
    type = "Replica",
    category,
    images = [],
    description = "",
    specs = "",
    isNewDrop = false,
    newDropUntil = null,
  } = body;

  if (!name || !category) {
    return Response.json(
      { error: "name and category are required" },
      { status: 400 }
    );
  }

  const result = await env.DB
    .prepare(`
      INSERT INTO products (name, type, category, images, description, specs, isNewDrop, newDropUntil)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .bind(
      name,
      type,
      category,
      JSON.stringify(images),
      description,
      specs,
      isNewDrop ? 1 : 0,
      newDropUntil
    )
    .run();

  return Response.json({ success: true, id: result.meta.last_row_id });
}
