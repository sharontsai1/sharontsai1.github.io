// 矮袋鼠小手帳 — food-scan proxy
//
// Why this exists at all: life-island.html is served from GitHub Pages, which is static.
// A Gemini API key in that page would be readable by anyone and billed to the user, so the
// key lives here as a Cloudflare secret and the page only ever talks to this Worker.
//
// Endpoints (all POST except /models):
//   POST /label   { image, mediaType }  -> nutrition panel read off a package
//   POST /photo   { image, mediaType }  -> calorie estimate from a plate of food
//   GET  /models                        -> which Gemini models this key can reach (debug)
//
// Every request must carry `Authorization: Bearer <Firebase ID token>`.

const PROJECT_ID = "selfrecord-d0708";
const JWKS_URL =
  "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const GEMINI = "https://generativelanguage.googleapis.com/v1beta";

// 8MB of base64 is ~6MB of image. The page downscales to ~1024px (a few hundred KB), so
// anything near this ceiling means the client-side resize silently didn't run.
const MAX_IMAGE_CHARS = 8 * 1024 * 1024;

const ALLOWED_MEDIA = ["image/jpeg", "image/png", "image/webp"];

// ---------------------------------------------------------------- CORS

function corsHeaders(request, env) {
  const allowed = (env.ALLOWED_ORIGINS || "https://sharontsai1.github.io")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const origin = request.headers.get("Origin") || "";
  // Echo the origin only when it is on the list — a bare "*" would let any page spend the quota.
  const allow = allowed.includes(origin) ? origin : allowed[0];
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

const json = (body, status, headers) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });

// ---------------------------------------------------------------- Firebase ID token

let jwksCache = { keys: null, until: 0 };

async function publicKeys() {
  if (jwksCache.keys && Date.now() < jwksCache.until) return jwksCache.keys;
  const r = await fetch(JWKS_URL);
  if (!r.ok) throw new AuthError("could not fetch Google public keys");
  const body = await r.json();
  const maxAge = /max-age=(\d+)/.exec(r.headers.get("cache-control") || "");
  jwksCache = {
    keys: body.keys || [],
    until: Date.now() + (maxAge ? +maxAge[1] : 3600) * 1000,
  };
  return jwksCache.keys;
}

class AuthError extends Error {}

function b64urlToBytes(s) {
  let t = s.replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  const raw = atob(t);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

// A token the client made up is a client error, not a server one: atob throws a DOMException
// and JSON.parse a SyntaxError, and letting either escape reports 500 for a bad request.
function decodeJson(part, what) {
  try {
    return JSON.parse(new TextDecoder().decode(b64urlToBytes(part)));
  } catch (e) {
    throw new AuthError(`token ${what} is not valid base64url JSON`);
  }
}

// Verifies the signature locally against Google's published keys. Doing it here rather than
// calling an identitytoolkit endpoint keeps it to one cached fetch per hour instead of a
// round trip on every scan.
async function verifyIdToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new AuthError("malformed token");

  const header = decodeJson(parts[0], "header");
  if (header.alg !== "RS256") throw new AuthError("unexpected token algorithm");

  const jwk = (await publicKeys()).find((k) => k.kid === header.kid);
  if (!jwk) throw new AuthError("token signed by an unknown key");

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const signed = new TextEncoder().encode(parts[0] + "." + parts[1]);
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlToBytes(parts[2]),
    signed
  );
  if (!ok) throw new AuthError("bad token signature");

  const p = decodeJson(parts[1], "payload");
  const now = Math.floor(Date.now() / 1000);
  if (!p.exp || p.exp <= now) throw new AuthError("token expired");
  if (p.iat && p.iat > now + 300) throw new AuthError("token issued in the future");
  if (p.aud !== PROJECT_ID) throw new AuthError("token is for another Firebase project");
  if (p.iss !== "https://securetoken.google.com/" + PROJECT_ID)
    throw new AuthError("unexpected token issuer");
  if (!p.sub) throw new AuthError("token has no subject");
  return p;
}

// A valid token only proves "some Google account signed into this Firebase project" — the
// sign-in is open, so anyone could get one. ALLOWED_UIDS is what restricts the quota to
// the owner. Left unset it logs the uid so it can be filled in.
function checkUid(uid, env) {
  const allowed = (env.ALLOWED_UIDS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!allowed.length) {
    console.log("ALLOWED_UIDS is unset — allowing uid", uid);
    return;
  }
  if (!allowed.includes(uid)) throw new AuthError("this account is not allowed");
}

// ---------------------------------------------------------------- model discovery

let modelCache = { list: null, until: 0 };
// The model that last answered successfully goes first next time, so one overloaded
// model costs a single extra round trip instead of one on every scan.
let lastGood = { name: null, until: 0 };
const MAX_ATTEMPTS = 6;
// Models Google has shut off still appear in the list endpoint; remember them per isolate.
const retired = new Set();
// An overloaded model can hang for over a minute before answering 503. Give up on it
// early so the next model still answers while the user is looking at the spinner.
const ATTEMPT_TIMEOUT_MS = 20000;
// Hedging: if the current model hasn't answered after this long, start the next one in
// parallel and take whichever succeeds first. The "last good" memory below is per isolate
// and Cloudflare recycles isolates often, so without this the slow path is the common one.
// Costs a few extra free-tier requests on bad days (quota ~1,000/day vs ~3 scans/day).
const HEDGE_MS = 6000;

// The model id is discovered rather than hardcoded: Gemini's names move (2.5 / 3 / 3.5 flash
// all exist in the wild) and a stale constant fails the whole feature with a 404. MODEL in
// wrangler.toml overrides this when a specific one is wanted.
// Returns candidate models best-first. A single model can be "experiencing high demand"
// (503) for hours, or out of free quota (429), while older flash models on the same key
// work fine; handleScan walks this list instead of failing the whole feature.
async function pickModels(env) {
  if (env.MODEL) return [env.MODEL];
  if (!(modelCache.list && Date.now() < modelCache.until)) {
    const r = await fetch(`${GEMINI}/models?key=${env.GEMINI_API_KEY}&pageSize=200`);
    if (!r.ok) throw new Error(`model list failed (${r.status}): ${await r.text()}`);
    const body = await r.json();
    const usable = (body.models || []).filter(
      (m) =>
        (m.supportedGenerationMethods || []).includes("generateContent") &&
        /^models\/gemini-\d/.test(m.name) && /flash/i.test(m.name) &&
        !/thinking|image|tts|native-audio|embedding|live/i.test(m.name)
    );
    if (!usable.length) throw new Error("no flash model with generateContent on this key");
    // Highest version first; within a version, full beats lite and stable beats preview.
    const score = (m) => {
      const v = /gemini-(\d+(?:\.\d+)?)/.exec(m.name);
      return (v ? parseFloat(v[1]) : 0) * 10 - (/lite/i.test(m.name) ? 2 : 0) - (/preview|exp/i.test(m.name) ? 1 : 0);
    };
    usable.sort((x, y) => score(y) - score(x));
    // Alternate full and lite models. Overload hits a whole tier at once (seen 2026-11-12:
    // every full 3.5–3.8 flash busy while every lite answered), so a strictly newest-first
    // list would spend all its attempts inside the one tier that is down.
    const names = usable.map((m) => m.name.replace(/^models\//, ""));
    const full = names.filter((n) => !/lite/i.test(n)), lite = names.filter((n) => /lite/i.test(n));
    const mixed = [];
    for (let i = 0; i < Math.max(full.length, lite.length); i++) {
      if (full[i]) mixed.push(full[i]);
      if (lite[i]) mixed.push(lite[i]);
    }
    modelCache = { list: mixed, until: Date.now() + 6 * 3600 * 1000 };
  }
  const list = modelCache.list.filter((n) => !retired.has(n));
  if (lastGood.name && Date.now() < lastGood.until && list.includes(lastGood.name))
    list.splice(list.indexOf(lastGood.name), 1), list.unshift(lastGood.name);
  return list;
}
async function pickModel(env) {
  return (await pickModels(env))[0];
}

// Worth trying another model: overloaded, out of quota for this model, or a transient
// server error. Anything else (bad image, schema, auth) would fail on every model too.
const isRetired = (e) => /no longer available|not found|is not supported/i.test(e.message || "");
const retryable = (e) => [429, 500, 502, 503, 504].includes(e.upstream) || isRetired(e) || /high demand|overloaded|unavailable/i.test(e.message || "");

// ---------------------------------------------------------------- prompts & schemas

// Labels state values per serving, per 100g, or for the whole pack, and a pack often holds
// more than one serving. Collapsing that to a single "calories" number is the main way this
// feature would quietly under-report, so the basis and the serving count are separate fields
// and the arithmetic happens on the page where the user can see it.
const LABEL_PROMPT = `You are reading a packaged food's nutrition panel from a photo. Reply in Traditional Chinese (zh-Hant) for any text fields.

Report energy, protein, fat and carbohydrate PER SINGLE SERVING. For carbohydrate use total carbohydrate (碳水化合物), not sugar.

- If the panel lists values per 100g/100ml and states a serving size, convert to per-serving and set basis to "converted_from_100g".
- If it lists values per serving directly, set basis to "per_serving".
- If it only gives whole-package values, put those in serving_kcal/serving_protein_g/serving_fat_g/serving_carbs_g, set servings_per_pack to 1 and basis to "per_pack".
- servings_per_pack is how many servings the package contains (本包裝含X份). Use 1 if it is a single-serving package. Never guess a number that is not derivable from the label.
- Convert kJ to kcal by dividing by 4.184 and say so in note.
- If the image is not a nutrition panel, or is too blurry to read the numbers, set ok to false and explain briefly in note. Do not invent numbers.

confidence is your own 0-1 estimate of how reliably you read the panel.`;

const LABEL_SCHEMA = {
  type: "object",
  properties: {
    ok: { type: "boolean" },
    product: { type: "string" },
    basis: {
      type: "string",
      enum: ["per_serving", "converted_from_100g", "per_pack", "unknown"],
    },
    serving_kcal: { type: "number" },
    serving_protein_g: { type: "number" },
    serving_fat_g: { type: "number" },
    serving_carbs_g: { type: "number" },
    serving_size: { type: "string" },
    servings_per_pack: { type: "number" },
    confidence: { type: "number" },
    note: { type: "string" },
  },
  required: ["ok", "product", "basis", "serving_kcal", "serving_protein_g", "serving_fat_g", "serving_carbs_g", "servings_per_pack", "confidence", "note"],
};

const PHOTO_PROMPT = `You are estimating the nutrition of a plate of food from a photo. Reply in Traditional Chinese (zh-Hant) for any text fields.

Portion size is genuinely hard to judge from an image, so:
- Break the meal into the dishes you can identify, each with its own kcal, protein, fat and carbohydrate estimate. Include cooking oil in fat.
- total_kcal_low and total_kcal_high must express your real uncertainty as a range, not a token spread around the midpoint. A rice bowl photographed from above can easily vary by a factor of two.
- Assume typical Taiwanese home or restaurant portions and cooking oil unless the photo clearly shows otherwise.
- If the image contains no food, set ok to false and say so in note. Do not invent a meal.

confidence is your own 0-1 estimate. Be honest and low when the portion is ambiguous.`;

const PHOTO_SCHEMA = {
  type: "object",
  properties: {
    ok: { type: "boolean" },
    meal_name: { type: "string" },
    items: {
      type: "array",
      items: {
        type: "object",
        properties: {
          name: { type: "string" },
          kcal: { type: "number" },
          protein_g: { type: "number" },
          fat_g: { type: "number" },
          carbs_g: { type: "number" },
        },
        required: ["name", "kcal", "protein_g", "fat_g", "carbs_g"],
      },
    },
    total_kcal: { type: "number" },
    total_protein_g: { type: "number" },
    total_fat_g: { type: "number" },
    total_carbs_g: { type: "number" },
    total_kcal_low: { type: "number" },
    total_kcal_high: { type: "number" },
    confidence: { type: "number" },
    note: { type: "string" },
  },
  required: ["ok", "meal_name", "items", "total_kcal", "total_protein_g", "total_fat_g", "total_carbs_g", "total_kcal_low", "total_kcal_high", "confidence", "note"],
};

// ---------------------------------------------------------------- Gemini

async function callGemini(env, model, prompt, schema, image, mediaType) {
  let r;
  try {
  r = await fetch(
    `${GEMINI}/models/${encodeURIComponent(model)}:generateContent?key=${env.GEMINI_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [
          {
            role: "user",
            parts: [
              { inline_data: { mime_type: mediaType, data: image } },
              { text: prompt },
            ],
          },
        ],
        generationConfig: {
          responseMimeType: "application/json",
          responseSchema: schema,
          temperature: 0,
        },
      }),
      signal: AbortSignal.timeout(ATTEMPT_TIMEOUT_MS),
    }
  );
  } catch (e) {
    const err = new Error(e.name === "TimeoutError" ? `${model} 超過 ${ATTEMPT_TIMEOUT_MS / 1000} 秒沒有回應` : e.message);
    err.status = 502;
    err.upstream = 504;   // treated as retryable: try the next model
    throw err;
  }

  const text = await r.text();
  if (!r.ok) {
    // Pass Gemini's own message through — "model not found" and "quota exceeded" need
    // completely different fixes and guessing between them wastes a debugging round.
    let detail = text.slice(0, 600);
    try {
      detail = JSON.parse(text).error?.message || detail;
    } catch {}
    const err = new Error(detail);
    err.status = r.status === 429 ? 429 : 502;
    err.upstream = r.status;
    throw err;
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Gemini returned a non-JSON body");
  }

  const blocked = parsed.promptFeedback?.blockReason;
  if (blocked) throw new Error(`Gemini declined this image (${blocked})`);

  const part = parsed.candidates?.[0]?.content?.parts?.find((p) => p.text);
  if (!part) {
    const why = parsed.candidates?.[0]?.finishReason || "no content";
    throw new Error(`Gemini returned no result (${why})`);
  }
  try {
    return JSON.parse(part.text);
  } catch {
    throw new Error("Gemini's result was not valid JSON despite the schema");
  }
}

// ---------------------------------------------------------------- handler

async function handleScan(request, env, kind, forceModel) {
  let body;
  try {
    body = await request.json();
  } catch {
    return { status: 400, body: { error: "body must be JSON" } };
  }

  const { image, mediaType } = body || {};
  if (typeof image !== "string" || !image)
    return { status: 400, body: { error: "image (base64, no data: prefix) is required" } };
  if (image.length > MAX_IMAGE_CHARS)
    return { status: 413, body: { error: "image too large — it should be downscaled before upload" } };
  if (!ALLOWED_MEDIA.includes(mediaType))
    return { status: 400, body: { error: `mediaType must be one of ${ALLOWED_MEDIA.join(", ")}` } };

  const [prompt, schema] =
    kind === "label" ? [LABEL_PROMPT, LABEL_SCHEMA] : [PHOTO_PROMPT, PHOTO_SCHEMA];
  // ?model= pins one model (owner-only, behind the uid lock) for diagnosing which ones answer.
  const models = forceModel ? [forceModel] : (await pickModels(env)).slice(0, MAX_ATTEMPTS);
  const tried = [];
  return await new Promise((resolve, reject) => {
    let next = 0, running = 0, done = false, stop = false, lastErr, timer;
    const finishFail = () => {
      done = true;
      clearTimeout(timer);
      lastErr.message = `${lastErr.message}（已試過 ${tried.join("、")}）`;
      reject(lastErr);
    };
    const hedge = () => {
      clearTimeout(timer);
      timer = setTimeout(() => { launch(); }, HEDGE_MS);
    };
    function launch() {
      if (done || stop || next >= models.length) return;
      const model = models[next++];
      running++;
      hedge();
      callGemini(env, model, prompt, schema, image, mediaType).then(
        (result) => {
          running--;
          if (done) return;
          done = true;
          clearTimeout(timer);
          lastGood = { name: model, until: Date.now() + 3600 * 1000 };
          resolve({ status: 200, body: { kind, model, tried, result } });
        },
        (e) => {
          running--;
          if (done) return;
          lastErr = e;
          tried.push(model + ":" + (e.upstream || "err"));
          console.log("model failed", model, e.upstream, e.message);
          if (isRetired(e)) retired.add(model);
          // A bad image or schema fails on every model, so don't spend more requests on it.
          if (!retryable(e)) stop = true;
          else launch();   // a fast failure moves on right away instead of waiting out the hedge
          if (running === 0 && (stop || next >= models.length)) finishFail();
        }
      );
    }
    launch();
  });
}

export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/" ) return json({ ok: true, service: "food-scan" }, 200, cors);

    if (!env.GEMINI_API_KEY)
      return json({ error: "GEMINI_API_KEY secret is not set on this Worker" }, 500, cors);

    // Auth first, so an unauthenticated caller can never reach the paid upstream.
    let claims;
    try {
      const auth = request.headers.get("Authorization") || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
      if (!token) throw new AuthError("missing Authorization: Bearer <Firebase ID token>");
      claims = await verifyIdToken(token);
      checkUid(claims.sub, env);
    } catch (e) {
      if (e instanceof AuthError) return json({ error: e.message }, 401, cors);
      return json({ error: "auth check failed: " + e.message }, 500, cors);
    }

    try {
      if (path === "/models" && request.method === "GET") {
        const r = await fetch(`${GEMINI}/models?key=${env.GEMINI_API_KEY}&pageSize=200`);
        const body = await r.json();
        return json(
          {
            picked: await pickModel(env).catch((e) => "ERROR: " + e.message),
            candidates: await pickModels(env).catch(() => []),
            uid: claims.sub,
            available: (body.models || [])
              .filter((m) => (m.supportedGenerationMethods || []).includes("generateContent"))
              .map((m) => m.name.replace(/^models\//, "")),
          },
          200,
          cors
        );
      }

      if (request.method !== "POST")
        return json({ error: "use POST" }, 405, cors);

      if (path === "/label" || path === "/photo") {
        const { status, body } = await handleScan(request, env, path.slice(1), url.searchParams.get("model"));
        return json(body, status, cors);
      }

      return json({ error: "unknown path " + path }, 404, cors);
    } catch (e) {
      const status = e.status || 500;
      console.log("scan failed", status, e.message);
      return json({ error: e.message, upstream: e.upstream }, status, cors);
    }
  },
};
