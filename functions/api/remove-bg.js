import { json, requireAdmin } from '../_lib/auth.js';

function getRemoveBgApiKey(env) {
  return env.REMOVEBG_API_KEY || env.REMOVE_BG_API_KEY || env.REMOVEBG_TOKEN || env.REMOVE_BG_TOKEN;
}

export async function onRequestPost({ request, env }) {
  const auth = await requireAdmin(request, env);
  if (auth.error) return auth.error;

  const apiKey = getRemoveBgApiKey(env);
  if (!apiKey) {
    return json(
      { error: 'Remove.bg API key is missing. Add REMOVEBG_API_KEY in Cloudflare secrets.' },
      { status: 500 }
    );
  }

  const { imageUrl } = await request.json();

  if (!imageUrl) {
    return json({ error: 'imageUrl is required' }, { status: 400 });
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
    return json({ error: errorText }, { status: removeBgResponse.status });
  }

  const imageBuffer = await removeBgResponse.arrayBuffer();

  return new Response(imageBuffer, {
    headers: {
      'Content-Type': 'image/png'
    }
  });
}
