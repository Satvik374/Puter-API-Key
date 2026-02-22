# Puter API Key Studio

Create and manage unlimited random API keys (`sk-...`) using a website dashboard.

How it works:
- You sign in with Puter first.
- The backend verifies your Puter token using `https://api.puter.com/whoami`.
- You can generate, list, and revoke as many keys as you want.
- Keys are stored in `data/api-store.json`.
- API calls use the Puter token of the account that created the key.

## 1) Install

```bash
npm install
```

## 2) Configure environment

Create `.env` from `.env.example`:

```env
PORT=3000
PUTER_API_ORIGIN=https://api.puter.com
SESSION_TTL_HOURS=24
```

Optional old fallback mode:

```env
PUTER_AUTH_TOKEN=...
APP_API_KEYS=sk_static_key
```

## 3) Run

```bash
npm run dev
```

Open:
- `http://localhost:3000`

## 4) Use the website

The dashboard is split into tabs: `Auth`, `Keys`, `Playground`, and `Templates`.

1. Click **Sign In With Puter**.
2. Create key(s) with random format like `sk-6fA2...`.
3. Copy a key and call:
   - `GET /v1/models`
   - `POST /v1/chat/completions`
   - `Authorization: Bearer <your-sk-key>`
4. Use **Terminal Template** section to copy ready-to-run Bash/PowerShell/CMD code.

## API Endpoints

- `POST /auth/puter/signin` - verify Puter token and create session
- `GET /auth/me` - current signed-in dashboard user
- `POST /auth/signout` - end dashboard session
- `GET /v1/keys` - list your keys
- `POST /v1/keys` - create a key
- `GET /v1/keys/:id/reveal` - reveal one key secret for copy
- `DELETE /v1/keys/:id` - revoke a key
- `GET /v1/models` - OpenAI-compatible model list for your API key
- `GET /v1/models/:model` - fetch one model by id
- `POST /v1/chat/completions` - call Puter model using API key

## Example Request

```bash
curl -X POST http://localhost:3000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk_your_key_here" \
  -d "{\"model\":\"gpt-5-nano\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}"
```

## Roo Code Setup (OpenAI Compatible)

In Roo Code, configure this server as an OpenAI-compatible provider:

1. Base URL: `http://localhost:3000/v1`
2. API Key: your generated `sk-...` key
3. Model: `gpt-5-nano` (or any id from `GET /v1/models`)

Compatibility notes:
- `POST /v1/chat/completions` now returns standard OpenAI-style JSON only (`choices[0].message.content`), with no custom `raw` field.
- `stream: true` is supported with SSE chunks and `[DONE]`, which Roo Code expects.

## Notes

- Keys can be copied any time from the dashboard.
- New keys store both hash (for auth check) and secret value (for copy/reveal).
- Older keys created before this update may show `No Secret`; create a new key if needed.
- If Puter token changes/expires, sign in again in the dashboard.
- `data/api-store.json` is git-ignored by default.
