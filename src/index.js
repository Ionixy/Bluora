export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/remove-bg" && request.method === "POST") {
      return handleRemoveBg(request, env);
    }

    return env.ASSETS.fetch(request);
  }
};

function isAuthorized(request, env) {
  if (!env.ADMIN_TOKEN) return true;
  return request.headers.get("x-admin-token") === env.ADMIN_TOKEN;
}

function getRemoveBgApiKey(env) {
  return env.REMOVEBG_API_KEY || env.REMOVE_BG_API_KEY || env.REMOVEBG_TOKEN || env.REMOVE_BG_TOKEN;
}

async function handleRemoveBg(request, env) {
  if (!isAuthorized(request, env)) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  const apiKey = getRemoveBgApiKey(env);
  if (!apiKey) {
    return Response.json(
      { error: "Remove.bg API key is missing. Add REMOVEBG_API_KEY in Cloudflare secrets." },
      { status: 500 }
    );
  }

  const { imageUrl } = await request.json();

  if (!imageUrl) {
    return Response.json({ error: "imageUrl is required" }, { status: 400 });
  }

  const form = new FormData();
  form.append("image_url", imageUrl);
  form.append("size", "auto");
  form.append("format", "png");

  const requestUrl = new URL(request.url);
  form.append("bg_image_url", `${requestUrl.origin}/bg.png`);

  const response = await fetch("https://api.remove.bg/v1.0/removebg", {
    method: "POST",
    headers: {
      "X-Api-Key": apiKey
    },
    body: form
  });

  if (!response.ok) {
    return Response.json(
      { error: await response.text() },
      { status: response.status }
    );
  }

  const image = await response.arrayBuffer();

  return new Response(image, {
    headers: {
      "Content-Type": "image/png"
    }
  });
}
