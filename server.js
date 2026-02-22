import crypto from "crypto";
import fs from "fs";
import path from "path";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import { init } from "@heyputer/puter.js/src/init.cjs";

dotenv.config();

const port = Number(process.env.PORT || 3000);
const puterApiOrigin = process.env.PUTER_API_ORIGIN || "https://api.puter.com";
const sessionTtlMs = Number(process.env.SESSION_TTL_HOURS || 24) * 60 * 60 * 1000;
const defaultChatModel =
  (process.env.DEFAULT_CHAT_MODEL || "").trim() || "gpt-5-nano";
const bootstrapPuterToken = (process.env.PUTER_AUTH_TOKEN || "").trim();
const bootstrapApiKeys = new Set(
  (process.env.APP_API_KEYS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
);
const storePath = path.join(process.cwd(), "data", "api-store.json");
const sessions = new Map();
const puterClientsByToken = new Map();
const app = express();

function ensureStore() {
  const dataDir = path.dirname(storePath);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  if (!fs.existsSync(storePath)) {
    fs.writeFileSync(
      storePath,
      JSON.stringify({ users: [], keys: [] }, null, 2),
      "utf8"
    );
  }
}

function loadStore() {
  ensureStore();
  try {
    const raw = fs.readFileSync(storePath, "utf8");
    const parsed = JSON.parse(raw);
    const users = Array.isArray(parsed?.users) ? parsed.users : [];
    const keys = Array.isArray(parsed?.keys) ? parsed.keys : [];
    return { users, keys };
  } catch {
    return { users: [], keys: [] };
  }
}

function saveStore(store) {
  ensureStore();
  fs.writeFileSync(storePath, JSON.stringify(store, null, 2), "utf8");
}

function randomChars(length) {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const bytes = crypto.randomBytes(length);
  let output = "";
  for (let i = 0; i < length; i += 1) {
    output += alphabet[bytes[i] % alphabet.length];
  }
  return output;
}

function generateApiKey() {
  return `sk-${randomChars(6)}${randomChars(6)}${randomChars(6)}${randomChars(6)}`;
}

function hashApiKey(apiKey) {
  return crypto.createHash("sha256").update(apiKey).digest("hex");
}

function getBearerToken(req) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) {
    return "";
  }
  return auth.slice("Bearer ".length).trim();
}

function getApiKeyFromRequest(req) {
  const bearer = getBearerToken(req);
  const xApiKey = (req.headers["x-api-key"] || "").toString().trim();
  const apiKeyHeader = (req.headers["api-key"] || "").toString().trim();
  return bearer || xApiKey || apiKeyHeader;
}

function createSessionToken() {
  return `sess_${crypto.randomUUID()}${randomChars(12)}`;
}

function getSession(req) {
  const sessionToken = getBearerToken(req);
  if (!sessionToken) {
    return null;
  }

  const session = sessions.get(sessionToken);
  if (!session) {
    return null;
  }

  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionToken);
    return null;
  }

  return { sessionToken, ...session };
}

function requireSession(req, res, next) {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({
      error: {
        message: "Sign in with Puter first",
        type: "unauthorized"
      }
    });
  }
  req.session = session;
  return next();
}

async function verifyPuterToken(puterToken) {
  const response = await fetch(`${puterApiOrigin}/whoami`, {
    headers: {
      Authorization: `Bearer ${puterToken}`
    }
  });

  if (!response.ok) {
    throw new Error("Invalid Puter token");
  }

  const user = await response.json();
  if (!user?.uuid || !user?.username) {
    throw new Error("Puter user not found");
  }

  return user;
}

function getPuterClient(puterToken) {
  if (!puterClientsByToken.has(puterToken)) {
    puterClientsByToken.set(puterToken, init(puterToken));
  }
  return puterClientsByToken.get(puterToken);
}

function findOwnerByApiKey(rawApiKey) {
  if (bootstrapApiKeys.has(rawApiKey) && bootstrapPuterToken) {
    return {
      source: "bootstrap",
      puterToken: bootstrapPuterToken,
      keyRecord: null
    };
  }

  const store = loadStore();
  const hashed = hashApiKey(rawApiKey);
  const keyRecord = store.keys.find(
    (record) => record.hash === hashed && !record.revokedAt
  );

  if (!keyRecord) {
    return null;
  }

  const owner = store.users.find((user) => user.id === keyRecord.userId);
  if (!owner?.puterToken) {
    return null;
  }

  return {
    source: "user",
    puterToken: owner.puterToken,
    keyRecord,
    ownerId: owner.id
  };
}

function requireApiKeyOwner(req, res) {
  const apiKey = getApiKeyFromRequest(req);
  if (!apiKey) {
    res.status(401).json({
      error: {
        message: "Missing API key",
        type: "invalid_api_key"
      }
    });
    return null;
  }

  const owner = findOwnerByApiKey(apiKey);
  if (!owner) {
    res.status(401).json({
      error: {
        message: "Invalid API key",
        type: "invalid_api_key"
      }
    });
    return null;
  }

  return owner;
}

function markKeyAsUsed(owner) {
  if (owner?.source !== "user" || !owner?.keyRecord?.id) {
    return;
  }

  const store = loadStore();
  const existing = store.keys.find((entry) => entry.id === owner.keyRecord.id);
  if (existing && !existing.revokedAt) {
    existing.lastUsedAt = new Date().toISOString();
    saveStore(store);
  }
}

function maskKey(prefix) {
  return `${prefix}****************`;
}

function extractText(value, seen = new WeakSet()) {
  if (typeof value === "string") {
    return value.trim();
  }

  if (Array.isArray(value)) {
    const parts = value
      .map((item) => extractText(item, seen))
      .filter((part) => typeof part === "string" && part.trim());
    return parts.join(" ").trim();
  }

  if (!value || typeof value !== "object") {
    return "";
  }

  if (seen.has(value)) {
    return "";
  }
  seen.add(value);

  const directKeys = ["text", "content", "value", "output_text"];
  for (const key of directKeys) {
    const field = value[key];
    if (typeof field === "string" && field.trim()) {
      return field.trim();
    }
  }

  const nestedKeys = [
    "text",
    "content",
    "value",
    "output_text",
    "delta",
    "message",
    "choice",
    "choices",
    "parts",
    "output",
    "messages",
    "response",
    "result"
  ];
  for (const key of nestedKeys) {
    if (value[key] === undefined) {
      continue;
    }
    const nested = extractText(value[key], seen);
    if (nested) {
      return nested;
    }
  }

  for (const nestedValue of Object.values(value)) {
    if (!nestedValue || typeof nestedValue !== "object") {
      continue;
    }
    const nested = extractText(nestedValue, seen);
    if (nested) {
      return nested;
    }
  }

  return "";
}

function normalizeContent(content) {
  return extractText(content);
}

function normalizeMessageValue(message) {
  if (message && typeof message === "object" && message.content !== undefined) {
    return normalizeContent(message.content);
  }
  return normalizeContent(message);
}

function normalizeModelOutput(result) {
  const extracted = normalizeContent(result);
  if (extracted) {
    return extracted;
  }
  try {
    return JSON.stringify(result);
  } catch {
    return String(result || "");
  }
}

function normalizeStreamChunkText(chunk) {
  return normalizeContent(chunk);
}

function getChatInput(body) {
  const messages = Array.isArray(body?.messages) ? body.messages : [];
  if (messages.length > 0) {
    return messages;
  }

  const prompt = typeof body?.prompt === "string" ? body.prompt : "";
  if (prompt.trim()) {
    return prompt;
  }

  return null;
}

function buildChatOptions(body, { stream = false } = {}) {
  const options = {
    model: (body?.model || defaultChatModel).toString().trim() || defaultChatModel
  };

  if (typeof body?.temperature === "number") {
    options.temperature = body.temperature;
  }
  if (typeof body?.max_tokens === "number") {
    options.max_tokens = body.max_tokens;
  }

  const passthroughFields = [
    "tools",
    "response",
    "reasoning",
    "reasoning_effort",
    "text",
    "verbosity",
    "provider"
  ];
  for (const key of passthroughFields) {
    if (body?.[key] !== undefined) {
      options[key] = body[key];
    }
  }

  if (stream) {
    options.stream = true;
  }

  return options;
}

function writeSseChunk(res, payload) {
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function mapModelRecord(model) {
  const id =
    model?.id || model?.model || model?.name || model?.slug || model?.model_name;
  if (typeof id !== "string" || !id.trim()) {
    return null;
  }

  const created =
    Number(
      model?.created ||
        model?.created_at ||
        model?.createdAt ||
        model?.timestamp ||
        0
    ) || 0;

  return {
    id: id.trim(),
    object: "model",
    created,
    owned_by: (model?.provider || model?.owned_by || "puter").toString()
  };
}

async function getOpenAIModelList(puter) {
  const models = await puter.ai.listModels();
  const mapped = Array.isArray(models)
    ? models.map((model) => mapModelRecord(model)).filter(Boolean)
    : [];

  if (!mapped.length) {
    return [
      {
        id: defaultChatModel,
        object: "model",
        created: 0,
        owned_by: "puter"
      }
    ];
  }

  const seen = new Set();
  return mapped.filter((model) => {
    if (seen.has(model.id)) {
      return false;
    }
    seen.add(model.id);
    return true;
  });
}

function mapProviderError(error) {
  const status =
    Number(
      error?.status ||
        error?.statusCode ||
        error?.response?.status ||
        error?.response?.statusCode ||
        error?.error?.status ||
        0
    ) || 0;

  const rawMessage =
    (error?.message || error?.error?.message || "Model request failed").toString();

  const codeHints = [
    error?.code,
    error?.name,
    error?.error?.code,
    error?.response?.data?.code,
    error?.response?.error?.code
  ]
    .filter(Boolean)
    .map((value) => value.toString().toLowerCase());

  const responsePayload =
    error?.response?.data ?? error?.response ?? error?.error ?? null;

  let payloadText = "";
  try {
    payloadText = responsePayload ? JSON.stringify(responsePayload) : "";
  } catch {
    payloadText = String(responsePayload || "");
  }

  const combined = `${rawMessage} ${payloadText} ${codeHints.join(" ")}`.toLowerCase();

  const isRateLimited =
    status === 429 ||
    combined.includes("rate limit") ||
    combined.includes("too many requests") ||
    combined.includes("quota") ||
    combined.includes("allowance") ||
    combined.includes("throttle") ||
    combined.includes("429") ||
    codeHints.some(
      (code) =>
        code.includes("rate") ||
        code.includes("quota") ||
        code.includes("allowance") ||
        code.includes("too_many_requests")
    );

  if (isRateLimited) {
    return {
      status: 429,
      type: "rate_limited",
      message:
        "You are rate limited by Puter right now. Please wait and retry.",
      providerStatus: status || 429
    };
  }

  if (
    status === 401 ||
    combined.includes("unauthorized") ||
    combined.includes("token") ||
    combined.includes("auth")
  ) {
    return {
      status: 401,
      type: "provider_auth_error",
      message:
        "Provider authentication failed. Sign in with Puter again and refresh your key.",
      providerStatus: status || 401
    };
  }

  if (
    status === 400 ||
    (combined.includes("model") &&
      (combined.includes("not found") ||
        combined.includes("unknown") ||
        combined.includes("invalid")))
  ) {
    return {
      status: 400,
      type: "invalid_model",
      message: "The selected model is invalid or unavailable.",
      providerStatus: status || 400
    };
  }

  return {
    status: 502,
    type: "provider_error",
    message: rawMessage,
    providerStatus: status || null
  };
}

ensureStore();
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.static("."));

app.get("/health", (_req, res) => {
  const store = loadStore();
  res.json({
    ok: true,
    service: "puter-ai-key-gateway",
    users: store.users.length,
    keys: store.keys.filter((key) => !key.revokedAt).length
  });
});

app.post("/auth/puter/signin", async (req, res) => {
  const puterToken = (req.body?.puterToken || "").trim();
  if (!puterToken) {
    return res.status(400).json({
      error: {
        message: "Missing puterToken",
        type: "invalid_request_error"
      }
    });
  }

  try {
    const whoami = await verifyPuterToken(puterToken);
    const store = loadStore();
    const existing = store.users.find((user) => user.id === whoami.uuid);
    if (existing?.puterToken && existing.puterToken !== puterToken) {
      puterClientsByToken.delete(existing.puterToken);
    }

    const userRecord = {
      id: whoami.uuid,
      username: whoami.username,
      puterToken,
      lastLoginAt: new Date().toISOString()
    };

    if (existing) {
      Object.assign(existing, userRecord);
    } else {
      store.users.push(userRecord);
    }

    saveStore(store);

    const sessionToken = createSessionToken();
    sessions.set(sessionToken, {
      userId: whoami.uuid,
      username: whoami.username,
      expiresAt: Date.now() + sessionTtlMs
    });

    return res.json({
      ok: true,
      sessionToken,
      user: {
        id: whoami.uuid,
        username: whoami.username
      }
    });
  } catch (error) {
    return res.status(401).json({
      error: {
        message: error?.message || "Puter sign-in failed",
        type: "auth_error"
      }
    });
  }
});

app.get("/auth/me", requireSession, (req, res) => {
  const store = loadStore();
  const user = store.users.find((entry) => entry.id === req.session.userId);
  if (!user) {
    return res.status(401).json({
      error: {
        message: "Session user no longer exists",
        type: "unauthorized"
      }
    });
  }

  const keyCount = store.keys.filter(
    (entry) => entry.userId === user.id && !entry.revokedAt
  ).length;

  return res.json({
    ok: true,
    user: {
      id: user.id,
      username: user.username
    },
    keyCount
  });
});

app.post("/auth/signout", requireSession, (req, res) => {
  sessions.delete(req.session.sessionToken);
  return res.json({ ok: true });
});

app.get("/v1/keys", requireSession, (req, res) => {
  const store = loadStore();
  const keys = store.keys
    .filter((entry) => entry.userId === req.session.userId && !entry.revokedAt)
    .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
    .map((entry) => ({
      id: entry.id,
      name: entry.name,
      prefix: entry.prefix,
      maskedKey: maskKey(entry.prefix),
      canCopy: Boolean(entry.value),
      createdAt: entry.createdAt,
      lastUsedAt: entry.lastUsedAt || null
    }));

  return res.json({ ok: true, keys });
});

app.post("/v1/keys", requireSession, (req, res) => {
  const name = (req.body?.name || "").toString().trim() || "Untitled Key";
  const keyValue = generateApiKey();
  const keyRecord = {
    id: `key_${crypto.randomUUID()}`,
    userId: req.session.userId,
    name,
    prefix: keyValue.slice(0, 10),
    value: keyValue,
    hash: hashApiKey(keyValue),
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
    revokedAt: null
  };

  const store = loadStore();
  store.keys.push(keyRecord);
  saveStore(store);

  return res.status(201).json({
    ok: true,
    key: {
      id: keyRecord.id,
      name: keyRecord.name,
      value: keyValue,
      maskedKey: maskKey(keyRecord.prefix),
      createdAt: keyRecord.createdAt
    }
  });
});

app.get("/v1/keys/:id/reveal", requireSession, (req, res) => {
  const store = loadStore();
  const keyRecord = store.keys.find(
    (entry) =>
      entry.id === req.params.id &&
      entry.userId === req.session.userId &&
      !entry.revokedAt
  );

  if (!keyRecord) {
    return res.status(404).json({
      error: {
        message: "Key not found",
        type: "not_found"
      }
    });
  }

  if (!keyRecord.value) {
    return res.status(409).json({
      error: {
        message:
          "This key was created before copy-anytime support. Create a new key to enable copy.",
        type: "key_secret_unavailable"
      }
    });
  }

  return res.json({
    ok: true,
    key: {
      id: keyRecord.id,
      value: keyRecord.value
    }
  });
});

app.delete("/v1/keys/:id", requireSession, (req, res) => {
  const store = loadStore();
  const keyRecord = store.keys.find(
    (entry) => entry.id === req.params.id && entry.userId === req.session.userId
  );

  if (!keyRecord || keyRecord.revokedAt) {
    return res.status(404).json({
      error: {
        message: "Key not found",
        type: "not_found"
      }
    });
  }

  keyRecord.revokedAt = new Date().toISOString();
  saveStore(store);
  return res.json({ ok: true });
});

async function handleModelsRequest(req, res) {
  const owner = requireApiKeyOwner(req, res);
  if (!owner) {
    return;
  }

  try {
    const puter = getPuterClient(owner.puterToken);
    const data = await getOpenAIModelList(puter);
    const requestedModelId =
      typeof req.params?.model === "string" ? req.params.model.trim() : "";

    if (requestedModelId) {
      const match = data.find((model) => model.id === requestedModelId);
      if (!match) {
        return res.status(404).json({
          error: {
            message: "Model not found",
            type: "invalid_model"
          }
        });
      }
      return res.json(match);
    }

    return res.json({
      object: "list",
      data
    });
  } catch (error) {
    const mapped = mapProviderError(error);
    return res.status(mapped.status).json({
      error: {
        message: mapped.message,
        type: mapped.type,
        provider_status: mapped.providerStatus
      }
    });
  }
}

app.get("/v1/models", handleModelsRequest);
app.get("/v1/models/:model", handleModelsRequest);
app.get("/models", handleModelsRequest);
app.get("/models/:model", handleModelsRequest);

async function handleChatCompletions(req, res) {
  const owner = requireApiKeyOwner(req, res);
  if (!owner) {
    return;
  }

  const stream = req.body?.stream === true;
  const input = getChatInput(req.body);
  if (!input) {
    return res.status(400).json({
      error: {
        message: "Provide either `prompt` or `messages`",
        type: "invalid_request_error"
      }
    });
  }

  try {
    const puter = getPuterClient(owner.puterToken);
    const completionId = `chatcmpl-${crypto.randomUUID()}`;
    const created = Math.floor(Date.now() / 1000);
    const options = buildChatOptions(req.body, { stream });
    const model = options.model;

    if (stream) {
      const streamResult = await puter.ai.chat(input, options);

      res.status(200);
      res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
      res.setHeader("Cache-Control", "no-cache, no-transform");
      res.setHeader("Connection", "keep-alive");
      if (typeof res.flushHeaders === "function") {
        res.flushHeaders();
      }

      writeSseChunk(res, {
        id: completionId,
        object: "chat.completion.chunk",
        created,
        model,
        choices: [
          {
            index: 0,
            delta: { role: "assistant" },
            finish_reason: null
          }
        ]
      });

      const isAsyncIterable =
        streamResult && typeof streamResult[Symbol.asyncIterator] === "function";

      let emittedText = "";
      let emittedAnyContent = false;

      if (isAsyncIterable) {
        for await (const chunk of streamResult) {
          const chunkText = normalizeStreamChunkText(chunk);
          if (!chunkText) {
            continue;
          }

          let deltaText = chunkText;
          if (chunkText.startsWith(emittedText)) {
            deltaText = chunkText.slice(emittedText.length);
            emittedText = chunkText;
          } else {
            emittedText += chunkText;
          }

          if (!deltaText) {
            continue;
          }

          emittedAnyContent = true;
          writeSseChunk(res, {
            id: completionId,
            object: "chat.completion.chunk",
            created,
            model,
            choices: [
              {
                index: 0,
                delta: { content: deltaText },
                finish_reason: null
              }
            ]
          });
        }
      } else {
        const content = normalizeModelOutput(streamResult);
        if (content) {
          emittedAnyContent = true;
          writeSseChunk(res, {
            id: completionId,
            object: "chat.completion.chunk",
            created,
            model,
            choices: [
              {
                index: 0,
                delta: { content },
                finish_reason: null
              }
            ]
          });
        }
      }

      if (!emittedAnyContent) {
        const fallbackContent = normalizeModelOutput(streamResult);
        if (fallbackContent) {
          writeSseChunk(res, {
            id: completionId,
            object: "chat.completion.chunk",
            created,
            model,
            choices: [
              {
                index: 0,
                delta: { content: fallbackContent },
                finish_reason: null
              }
            ]
          });
        }
      }

      writeSseChunk(res, {
        id: completionId,
        object: "chat.completion.chunk",
        created,
        model,
        choices: [
          {
            index: 0,
            delta: {},
            finish_reason: "stop"
          }
        ]
      });
      res.write("data: [DONE]\n\n");

      markKeyAsUsed(owner);
      res.end();
      return;
    }

    const raw = await puter.ai.chat(input, options);
    const content = normalizeModelOutput(raw);

    markKeyAsUsed(owner);

    return res.json({
      id: completionId,
      object: "chat.completion",
      created,
      model,
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content
          },
          finish_reason: "stop"
        }
      ]
    });
  } catch (error) {
    const mapped = mapProviderError(error);

    if (stream && res.headersSent) {
      writeSseChunk(res, {
        error: {
          message: mapped.message,
          type: mapped.type,
          provider_status: mapped.providerStatus
        }
      });
      res.write("data: [DONE]\n\n");
      res.end();
      return;
    }

    return res.status(mapped.status).json({
      error: {
        message: mapped.message,
        type: mapped.type,
        provider_status: mapped.providerStatus
      }
    });
  }
}

app.post("/v1/chat/completions", handleChatCompletions);
app.post("/chat/completions", handleChatCompletions);

app.listen(port, () => {
  console.log(`Gateway running on http://localhost:${port}`);
});

