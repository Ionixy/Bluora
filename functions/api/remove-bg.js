function isAuthorized(request, env) {
  if (!env.ADMIN_TOKEN) return true;
  const token = request.headers.get('x-admin-token');
  return token === env.ADMIN_TOKEN;
}

function getRemoveBgApiKey(env) {
  return env.REMOVEBG_API_KEY || env.REMOVE_BG_API_KEY || env.REMOVEBG_TOKEN || env.REMOVE_BG_TOKEN;
}

export async function onRequestPost({ request, env }) {
  if (!isAuthorized(request, env)) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const apiKey = getRemoveBgApiKey(env);
  if (!apiKey) {
    return Response.json(
      { error: 'Remove.bg API key is missing. Add REMOVEBG_API_KEY in Cloudflare secrets.' },
      { status: 500 }
    );
  }

  const { imageUrl } = await request.json();

  if (!imageUrl) {
    return Response.json({ error: 'imageUrl is required' }, { status: 400 });
  }

  const form = new FormData();
  form.append('image_url', imageUrl);
  form.append('size', 'auto');
  form.append('format', 'png');

  const removeBgResponse = await fetch('https://api.remove.bg/v1.0/removebg', {
    method: 'POST',
    headers: {
      'X-Api-Key': apiKey
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
