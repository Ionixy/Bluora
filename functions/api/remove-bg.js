function isAuthorized(request, env) {
  const token = request.headers.get('x-admin-token');
  return token === env.ADMIN_TOKEN;
}

export async function onRequestPost({ request, env }) {
  if (!isAuthorized(request, env)) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { imageUrl } = await request.json();

  if (!imageUrl) {
    return Response.json({ error: 'imageUrl is required' }, { status: 400 });
  }

  const form = new FormData();
  form.append('image_url', imageUrl);
  form.append('size', 'auto');
  form.append('format', 'png');

  // Автоматически определяем адрес сайта и указываем путь к bg.jpg
  const requestUrl = new URL(request.url);
  const bgImageUrl = `${requestUrl.origin}/bg.jpg`;
  form.append('bg_image_url', bgImageUrl);

  const removeBgResponse = await fetch('https://api.remove.bg/v1.0/removebg', {
    method: 'POST',
    headers: {
      'X-Api-Key': env.92JHGBJjxPDMuXHcRqRK2gdn
    },
    body: form
  });

  if (!removeBgResponse.ok) {
    const errorText = await removeBgResponse.text();
    return Response.json({ error: errorText }, { status: removeBgResponse.status });
  }

  const imageBuffer = await removeBgResponse.arrayBuffer();

  return new Response(imageBuffer, {
    headers: {
      'Content-Type': 'image/png'
    }
  });
}
