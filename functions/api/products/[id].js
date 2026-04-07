export async function onRequestPut(context) {
  const { env, request, params } = context;
  const id = Number(params.id);
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

  await env.DB
    .prepare(`
      UPDATE products
      SET name = ?, type = ?, category = ?, images = ?, description = ?, specs = ?, isNewDrop = ?, newDropUntil = ?
      WHERE id = ?
    `)
    .bind(
      name,
      type,
      category,
      JSON.stringify(images),
      description,
      specs,
      isNewDrop ? 1 : 0,
      newDropUntil,
      id
    )
    .run();

  return Response.json({ success: true });
}

export async function onRequestDelete(context) {
  const { env, params } = context;
  const id = Number(params.id);

  await env.DB
    .prepare("DELETE FROM products WHERE id = ?")
    .bind(id)
    .run();

  return Response.json({ success: true });
}