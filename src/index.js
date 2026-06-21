export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/remove-bg" && request.method === "POST") {
      return handleRemoveBg(request, env);
    }

    return env.ASSETS.fetch(request);
  }
};

async function handleRemoveBg(request, env) {
  const { imageUrl } = await request.json();

  if (!imageUrl) {
    return Response.json({ error: "imageUrl is required" }, { status: 400 });
  }

  const form = new FormData();
  form.append("image_url", imageUrl);
  form.append("size", "auto");
  form.append("format", "png");

  const response = await fetch("https://api.remove.bg/v1.0/removebg", {
    method: "POST",
    headers: {
      "X-Api-Key": env.REMOVEBG_API_KEY
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