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

function maskKey(prefix) {
  return `${prefix}****************`;
}

function normalizeContent(content) {
  if (typeof content === "string") {
    return content;
  }
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === "string") {
          return part;
        }
        if (part && typeof part.text === "string") {
          return part.text;
        }
        return "";
      })
      .join(" ")
      .trim();
  }
  return "";
}

function messagesToPrompt(messages) {
  if (!Array.isArray(messages) || messages.length === 0) {
    return "";
  }

  return messages
    .map((message) => {
      const role = (message?.role || "user").toString().toUpperCase();
      const content = normalizeContent(message?.content);
      return `[${role}] ${content}`;
    })
    .join("\n");
}

function normalizeModelOutput(result) {
  if (typeof result === "string") {
    return result;
  }
  if (result && typeof result.text === "string") {
    return result.text;
  }
  if (result && typeof result.message === "string") {
    return result.message;
  }
  return JSON.stringify(result);
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

app.post("/v1/chat/completions", async (req, res) => {
  const bearer = getBearerToken(req);
  const fallback = (req.headers["x-api-key"] || "").toString().trim();
  const apiKey = bearer || fallback;

  if (!apiKey) {
    return res.status(401).json({
      error: {
        message: "Missing API key",
        type: "invalid_api_key"
      }
    });
  }

  const owner = findOwnerByApiKey(apiKey);
  if (!owner) {
    return res.status(401).json({
      error: {
        message: "Invalid API key",
        type: "invalid_api_key"
      }
    });
  }

  const model = req.body?.model || "gpt-5-nano";
  const prompt =
    typeof req.body?.prompt === "string"
      ? req.body.prompt
      : messagesToPrompt(req.body?.messages);

  if (!prompt || !prompt.trim()) {
    return res.status(400).json({
      error: {
        message: "Provide either `prompt` or `messages`",
        type: "invalid_request_error"
      }
    });
  }

  try {
    const puter = getPuterClient(owner.puterToken);
    const raw = await puter.ai.chat(prompt, { model });
    const content = normalizeModelOutput(raw);

    if (owner.source === "user" && owner.keyRecord?.id) {
      const store = loadStore();
      const existing = store.keys.find((entry) => entry.id === owner.keyRecord.id);
      if (existing && !existing.revokedAt) {
        existing.lastUsedAt = new Date().toISOString();
        saveStore(store);
      }
    }

    return res.json({
      id: `chatcmpl-${crypto.randomUUID()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
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
      ],
      raw
    });
  } catch (error) {
    return res.status(500).json({
      error: {
        message: error?.message || "Model request failed",
        type: "provider_error"
      }
    });
  }
});

app.listen(port, () => {
  console.log(`Gateway running on http://localhost:${port}`);
});
