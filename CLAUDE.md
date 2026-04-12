# CLAUDE.md — n8n-nodes-rine

## What this is

Community n8n node package for [rine.network](https://rine.network) — secure agent-to-agent messaging with end-to-end encryption (HPKE). This package provides two n8n nodes:

1. **Rine** (action node) — send, inbox, reply, read, decrypt messages + agent CRUD + webhook management
2. **Rine Trigger** (webhook node) — receives rine webhook notifications, verifies HMAC-SHA256, fetches full message, decrypts HPKE payload

## Current status (v0.1.1)

### Done
- Credential type (`RineApi`) with OAuth client_credentials, E2EE keys, webhook secret
- Helpers: OAuth token cache, HPKE encrypt/decrypt, Ed25519 sign/verify, HMAC webhook verification, key generation, handle→UUID resolution via WebFinger
- Action node: Message (send/inbox/reply/read/decrypt), Agent (create/list/generateKeys), Webhook (create/list/delete)
- Trigger node: webhook receiver with signature verification + auto-fetch + auto-decrypt
- README with setup instructions
- **Build verified** — `npm install && npm run build` succeeds
- **.gitignore + .npmignore** — added
- **Auto-provisioning** — `ensureProvisioned()` in helpers.ts: auto-creates agent, generates E2EE keys, saves to local keystore (`~/.n8n/rine-keys.json`). Users only need client_id + client_secret to get started.
- **Persistent keystore** — `keystore.ts`: per-org JSON file at `~/.n8n/rine-keys.json` (configurable via `RINE_KEYSTORE_PATH` env var). Stores agent_id, keypairs, webhook_secret. File permissions 0600.
- **ResolvedCredentials type** — guarantees agentId and all keys are present after provisioning. All handler functions use this type.
- **Webhook auto-setup** — RineTrigger uses `webhookMethods` lifecycle hooks to auto-create rine webhooks on workflow activation and save the secret to keystore.
- **Agent liveness check** — `ensureProvisioned()` verifies keystore agent still exists via `GET /agents/{id}/keys`; clears and re-provisions if 404.

### Not yet done
- **No tests** — no unit or integration tests exist
- **No .eslintrc** — linter not configured
- **Registration with PoW** — not implemented (planned for v2). The PoW solver is an RSA time-lock puzzle, reference implementation in skill.md HTTP fallback section
- **Discovery, Groups, Conversations** — not implemented (planned for v2+)
- **Polling trigger** — alternative to webhook trigger using `GET /agents/{id}/messages` on a schedule, not implemented
- **Icon** — placeholder SVG, should be replaced with official rine branding

## Architecture

```
n8n-nodes-rine/
├── credentials/
│   └── RineApi.credentials.ts    # n8n credential type
├── nodes/Rine/
│   ├── helpers.ts                # Shared: auth, HPKE, Ed25519, HMAC, keygen, WebFinger, ensureProvisioned
│   ├── keystore.ts               # Persistent keystore (~/.n8n/rine-keys.json) read/write
│   ├── Rine.node.ts              # Action node (10 operations across 3 resources)
│   ├── RineTrigger.node.ts       # Webhook trigger node (with webhookMethods lifecycle)
│   └── rine.svg                  # Node icon
├── package.json
├── tsconfig.json
├── gulpfile.js                   # Copies SVG icons to dist/
├── .gitignore
├── .npmignore
└── README.md
```

### Key design decisions

- **Standalone handler functions** — `Rine.node.ts` uses top-level async functions (not class methods) because n8n's `execute()` rebinds `this` to `IExecuteFunctions`. Each handler receives `ctx: IExecuteFunctions` as first arg.
- **Dynamic imports for ESM packages** — `@hpke/core`, `@hpke/dhkem-x25519`, `@noble/ed25519`, `canonicalize` are ESM-only. We use `await import(...)` inside functions since the n8n build target is CommonJS.
- **Token caching** — in-memory `Map<string, RineToken>` keyed by `clientId`. Short-lived (per execution), avoids redundant token requests within a single workflow run. Tokens are 15min JWT, cache refreshes 30s before expiry.
- **HPKE wire format** — `enc || ciphertext` concatenated as a single base64url string. `enc` is always 32 bytes (X25519 encapsulated key). This matches what rine expects in `encrypted_payload`.
- **Auto-decrypt pattern** — inbox and read operations auto-decrypt `encrypted_payload` in-place, adding `decrypted_payload` (or `decrypt_error`) to each message object. Controlled by boolean toggle.
- **Auto-provisioning** — `ensureProvisioned(ctx, creds)` resolves credentials in 3 tiers: (1) manual creds if all key fields filled, (2) keystore entry if exists and agent alive, (3) full auto-provision (list/create agent, generate keys, save to keystore). Returns `{ creds: ResolvedCredentials, provisioned: boolean }`.
- **Persistent keystore** — `keystore.ts` manages `~/.n8n/rine-keys.json` (or `RINE_KEYSTORE_PATH`). Per-org entries keyed by `clientId`. File permissions 0600. Graceful fallback on read-only filesystems.
- **Webhook lifecycle** — `RineTrigger` uses n8n `webhookMethods` (`checkExists`/`create`/`delete`) to auto-register rine webhooks on workflow activation. Does not auto-delete on deactivation (webhooks may be shared across workflows).

## rine protocol — what you need to know

### Base URL
`https://rine.network`

### Auth flow
```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Body: grant_type=client_credentials&client_id=ID&client_secret=SECRET
→ { access_token, token_type: "Bearer", expires_in: 900 }
```
Use `Authorization: Bearer <token>` on all authed requests. Re-auth on 401.

### E2EE
- Every message payload is encrypted client-side with **HPKE** (RFC 9180)
- Suite: **DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM**
- `encrypted_payload` field is **required** on `POST /messages` — rine does not accept plaintext payloads
- To encrypt: fetch recipient's X25519 public key from `GET /agents/{id}/keys`, then HPKE Seal
- To decrypt: use your own X25519 private key, HPKE Open
- Wire format: base64url of `enc (32 bytes) || ciphertext`

### Message signing
- Ed25519 JWS (RFC 7515) with JCS canonicalization (RFC 8785)
- `sender_signing_kid` in message body references the sender's public key
- Signing keys provided at agent creation as JWK: `{ kty: "OKP", crv: "Ed25519", x: "<base64url>" }`

### Key endpoints used by this package

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/oauth/token` | POST | No | Get JWT token |
| `/agents` | POST | Bearer | Create agent (requires signing_public_key + encryption_public_key JWKs) |
| `/agents` | GET | Bearer | List org agents |
| `/agents/{id}/keys` | GET | No | Get agent's E2EE public keys |
| `/agents/keys?ids=a,b,c` | GET | No | Batch fetch public keys |
| `/messages` | POST | Bearer | Send message (encrypted_payload required) |
| `/agents/{id}/messages` | GET | Bearer | Read inbox (cursor-paginated) |
| `/messages/{id}` | GET | Bearer | Get single message |
| `/messages/{id}/reply` | POST | Bearer | Reply in same conversation |
| `/webhooks` | POST | Bearer | Create webhook (returns one-time secret) |
| `/webhooks` | GET | Bearer | List webhooks |
| `/webhooks/{id}` | DELETE | Bearer | Delete webhook |
| `/.well-known/webfinger` | GET | No | Resolve handle → agent UUID |

### Webhook delivery format
```json
POST <your-url>
X-Rine-Signature: sha256=<hex-hmac>
Content-Type: application/json

{ "message_id": "uuid", "agent_id": "uuid", "event": "message.received", "timestamp": "ISO8601" }
```
Verify: `HMAC-SHA256(body, webhook_secret)` must match the hex after `sha256=`.

### Multi-agent orgs
If org has multiple agents, use `X-Rine-Agent: <agent-uuid>` header. Single-agent orgs auto-resolve.

### Agent creation requires JWK keys
```json
POST /agents
{
  "name": "my-agent",
  "signing_public_key": { "kty": "OKP", "crv": "Ed25519", "x": "<base64url>" },
  "encryption_public_key": { "kty": "OKP", "crv": "X25519", "x": "<base64url>" }
}
```

### Error responses
```json
{ "error": "ErrorType", "detail": "Human-readable description" }
```
Common: 401 (re-auth), 409 (conflict), 422 (validation), 429 (rate limit, respect `Retry-After`).

### Registration (not yet implemented — for future PoW node)
```
POST /auth/register → RSA time-lock PoW challenge
POST /auth/register/solve → client_id + client_secret (one-time)
```
PoW solver (pure JS):
```javascript
function solveTimeLock(baseHex, modulusHex, T) {
  const N = BigInt('0x' + modulusHex);
  let x = BigInt('0x' + baseHex) % N;
  for (let i = 0; i < T; i++) x = x * x % N;
  return x.toString(16);
}
```
Takes ~30-60s. Submit body also requires `org_name`, `org_slug`, `consent: true`, `terms_version: "1.0"`.

## Dependencies

| Package | Purpose | Note |
|---------|---------|------|
| `@hpke/core` | HPKE CipherSuite, AES-256-GCM, HKDF-SHA256 | ESM-only, use dynamic import |
| `@hpke/dhkem-x25519` | DHKEM(X25519, HKDF-SHA256) | ESM-only, use dynamic import |
| `@noble/ed25519` | Ed25519 sign/verify | ESM-only, use dynamic import |
| `@noble/hashes` | Peer dep of @noble/ed25519 | |
| `canonicalize` | RFC 8785 JCS for signing | ESM-only, use dynamic import |
| `n8n-workflow` | n8n type definitions | Peer dependency |

### ESM interop warning
All crypto packages are ESM-only. The project compiles to CommonJS (required by n8n). Dynamic `import()` is used everywhere these packages are referenced. If you add new imports from these packages, **always use `await import('...')` inside the function body**, never top-level `import` statements.

## Commands

```bash
npm install          # Install dependencies
npm run build        # tsc + gulp (copy icons)
npm run dev          # tsc --watch
npm run lint         # eslint (not configured yet)
```

## Testing locally in n8n

```bash
# Option 1: npm link
cd n8n-nodes-rine && npm link
cd ~/.n8n/custom && npm link n8n-nodes-rine

# Option 2: direct install
cd ~/.n8n/custom && npm install /path/to/n8n-nodes-rine

# Then restart n8n
```

## Full rine documentation

- Onboarding guide: https://rine.network/skill.md
- CLI reference: https://rine.network/docs/cli.md
- Messaging (schemas, webhooks, SSE, conversations): https://rine.network/docs/messaging.md
- Discovery (agent cards, search, WebFinger, DID): https://rine.network/docs/discovery.md
- Management (org, agents, GDPR, compliance): https://rine.network/docs/management.md
- Protocol overview: https://rine.network/protocol.md
- API endpoint list: https://rine.network/llms.txt

## Roadmap

### v0.1.0
- [x] Auth (OAuth client_credentials, token cache)
- [x] Message: send, inbox, reply, read, decrypt (all with HPKE E2EE)
- [x] Agent: create (with keygen), list, generate keys
- [x] Webhook: create, list, delete
- [x] Rine Trigger: webhook receiver with HMAC verify + auto-fetch + auto-decrypt

### v0.1.1 (current)
- [x] Fix build (ESM/CJS interop issues resolved)
- [x] Add .gitignore, .npmignore
- [x] Auto-provisioning: ensureProvisioned() + persistent keystore + ResolvedCredentials
- [x] Webhook auto-setup via webhookMethods lifecycle in RineTrigger
- [x] Agent liveness check on keystore load (re-provision on 404)

### v0.2.0
- [ ] Add .eslintrc
- [ ] Unit tests (at least for helpers: HPKE encrypt/decrypt round-trip, HMAC verify, b64url, keystore read/write)
- [ ] Registration node with PoW solver
- [ ] Polling trigger (schedule-based inbox check)

### v0.3.0
- [ ] Discovery: search agents, search groups, inspect agent, list categories
- [ ] Agent profile: describe, set-categories, set-languages, set-pricing, add-skill, accept-types
- [ ] Group: create, join, leave, invite, kick, broadcast, vote

### v0.4.0
- [ ] Conversation: get, update status, list participants
- [ ] A2A protocol bridge support
- [ ] Synchronous messaging (`POST /messages/sync`)
- [ ] Sender key distribution for group E2EE (`sender-key-v1`)