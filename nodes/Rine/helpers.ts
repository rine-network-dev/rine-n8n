/**
 * rine helpers — auth, E2EE (HPKE), signing (Ed25519)
 *
 * These are shared across Rine.node.ts and RineTrigger.node.ts.
 */

import { IExecuteFunctions, IWebhookFunctions, IHookFunctions } from 'n8n-workflow';
import { getOrgEntry, saveOrgEntry, clearOrgEntry, KeystoreEntry } from './keystore';

export { getKeystorePath, updateOrgEntry, getAgentEntry } from './keystore';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RineToken {
	accessToken: string;
	expiresAt: number; // epoch ms
}

const DEFAULT_BASE_URL = 'https://rine.network';

export interface RineCredentials {
	baseUrl?: string;
	clientId: string;
	clientSecret: string;
	agentId?: string;
	signingPrivateKey?: string;
	signingPublicKey?: string;
	encryptionPrivateKey?: string;
	encryptionPublicKey?: string;
	webhookSecret?: string;
}

/** Resolve baseUrl with fallback to default */
export function resolveBaseUrl(creds: RineCredentials): string {
	return creds.baseUrl || DEFAULT_BASE_URL;
}

export interface ResolvedCredentials {
	baseUrl: string;
	clientId: string;
	clientSecret: string;
	agentId: string;
	agentHandle?: string;
	signingPrivateKey: string;
	signingPublicKey: string;
	encryptionPrivateKey: string;
	encryptionPublicKey: string;
	webhookSecret?: string;
}

export type RineContext = IExecuteFunctions | IWebhookFunctions | IHookFunctions;

// In-memory token cache (per execution — n8n nodes are short-lived,
// but this avoids double-fetching within a single execution).
const tokenCache = new Map<string, RineToken>();

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export async function getAccessToken(
	ctx: RineContext,
	creds: RineCredentials,
): Promise<string> {
	const cacheKey = creds.clientId;
	const cached = tokenCache.get(cacheKey);
	if (cached && cached.expiresAt > Date.now() + 30_000) {
		return cached.accessToken;
	}

	const baseUrl = resolveBaseUrl(creds);
	const response = await ctx.helpers.httpRequest({
		method: 'POST',
		url: `${baseUrl}/oauth/token`,
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: `grant_type=client_credentials&client_id=${encodeURIComponent(creds.clientId)}&client_secret=${encodeURIComponent(creds.clientSecret)}`,
		returnFullResponse: false,
		json: true,
	});

	const token: RineToken = {
		accessToken: response.access_token,
		expiresAt: Date.now() + (response.expires_in ?? 900) * 1000,
	};
	tokenCache.set(cacheKey, token);
	return token.accessToken;
}

// ---------------------------------------------------------------------------
// Base64url utilities
// ---------------------------------------------------------------------------

export function b64urlEncode(buf: Uint8Array | Buffer): string {
	const b64 = Buffer.from(buf).toString('base64');
	return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(s: string): Uint8Array {
	let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
	while (b64.length % 4) b64 += '=';
	return new Uint8Array(Buffer.from(b64, 'base64'));
}

// ---------------------------------------------------------------------------
// JWK helpers
// ---------------------------------------------------------------------------

export function ed25519PubJwk(pubB64url: string): object {
	return { kty: 'OKP', crv: 'Ed25519', x: pubB64url };
}

export function x25519PubJwk(pubB64url: string): object {
	return { kty: 'OKP', crv: 'X25519', x: pubB64url };
}

// ---------------------------------------------------------------------------
// HPKE Encrypt / Decrypt
// ---------------------------------------------------------------------------

/**
 * Encrypt a JSON payload for a recipient using HPKE
 * (X25519 + HKDF-SHA256 + AES-256-GCM, which is DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM).
 *
 * Returns base64url-encoded ciphertext.
 */
export async function hpkeEncrypt(
	plaintext: string,
	recipientPubKeyB64url: string,
): Promise<string> {
	// Dynamic imports — these are ESM-only packages
	const { CipherSuite } = await import('@hpke/core');
	const { DhkemX25519HkdfSha256 } = await import('@hpke/dhkem-x25519');

	// Use AES-256-GCM from @hpke/core (default AEAD)
	const { Aes256Gcm, HkdfSha256 } = await import('@hpke/core');

	const suite = new CipherSuite({
		kem: new DhkemX25519HkdfSha256(),
		kdf: new HkdfSha256(),
		aead: new Aes256Gcm(),
	});

	const recipientPubBytes = b64urlDecode(recipientPubKeyB64url);

	// Import the recipient's X25519 public key
	const recipientPub = await suite.kem.importKey('raw', recipientPubBytes, true);

	// Seal (single-shot encrypt)
	const sender = await suite.createSenderContext({ recipientPublicKey: recipientPub });

	const ct = await sender.seal(new TextEncoder().encode(plaintext));

	// Concatenate enc || ct for transport
	// enc = encapsulated key (32 bytes for X25519)
	const enc = new Uint8Array(sender.enc);
	const combined = new Uint8Array(enc.length + ct.byteLength);
	combined.set(enc, 0);
	combined.set(new Uint8Array(ct), enc.length);

	return b64urlEncode(combined);
}

/**
 * Decrypt a base64url HPKE ciphertext using our X25519 private key.
 *
 * Returns plaintext string.
 */
export async function hpkeDecrypt(
	ciphertextB64url: string,
	privateKeyB64url: string,
): Promise<string> {
	const { CipherSuite } = await import('@hpke/core');
	const { DhkemX25519HkdfSha256 } = await import('@hpke/dhkem-x25519');
	const { Aes256Gcm, HkdfSha256 } = await import('@hpke/core');

	const suite = new CipherSuite({
		kem: new DhkemX25519HkdfSha256(),
		kdf: new HkdfSha256(),
		aead: new Aes256Gcm(),
	});

	const combined = b64urlDecode(ciphertextB64url);

	// First 32 bytes = enc (encapsulated key), rest = ciphertext
	const ENC_LEN = 32;
	const enc = combined.slice(0, ENC_LEN);
	const ct = combined.slice(ENC_LEN);

	const privBytes = b64urlDecode(privateKeyB64url);
	const recipientPriv = await suite.kem.importKey('raw', privBytes, false);

	const recipient = await suite.createRecipientContext({
		recipientKey: recipientPriv,
		enc,
	});

	const pt = await recipient.open(ct);
	return new TextDecoder().decode(pt);
}

// ---------------------------------------------------------------------------
// Ed25519 Signing (JWS Compact — RFC 7515 with JCS canonicalization)
// ---------------------------------------------------------------------------

/**
 * Sign a payload object using Ed25519.
 * Uses RFC 8785 JSON Canonicalization Scheme (JCS) before signing.
 * Returns a JWS compact serialization string.
 */
export async function ed25519Sign(
	payload: object,
	privateKeyB64url: string,
	keyId?: string,
): Promise<string> {
	const ed = await import('@noble/ed25519');
	const canonicalize = (await import('canonicalize')).default;

	const header: Record<string, string> = { alg: 'EdDSA', typ: 'JWS' };
	if (keyId) header.kid = keyId;

	const headerB64 = b64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
	const canonical = canonicalize(payload) as string;
	const payloadB64 = b64urlEncode(new TextEncoder().encode(canonical));

	const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
	const privBytes = b64urlDecode(privateKeyB64url);
	const sig = await ed.signAsync(signingInput, privBytes);

	return `${headerB64}.${payloadB64}.${b64urlEncode(sig)}`;
}

/**
 * Verify a JWS compact serialization against an Ed25519 public key.
 * Returns the parsed payload if valid, throws otherwise.
 */
export async function ed25519Verify(
	jws: string,
	publicKeyB64url: string,
): Promise<object> {
	const ed = await import('@noble/ed25519');

	const [headerB64, payloadB64, sigB64] = jws.split('.');
	if (!headerB64 || !payloadB64 || !sigB64) {
		throw new Error('Invalid JWS compact serialization');
	}

	const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
	const sig = b64urlDecode(sigB64);
	const pubBytes = b64urlDecode(publicKeyB64url);

	const valid = await ed.verifyAsync(sig, signingInput, pubBytes);
	if (!valid) throw new Error('Ed25519 signature verification failed');

	const payloadJson = new TextDecoder().decode(b64urlDecode(payloadB64));
	return JSON.parse(payloadJson);
}

// ---------------------------------------------------------------------------
// Webhook HMAC verification
// ---------------------------------------------------------------------------

export function verifyWebhookSignature(
	rawBody: string | Buffer,
	signatureHeader: string,
	secret: string,
): boolean {
	const crypto = require('crypto');
	const expected = signatureHeader.replace('sha256=', '');
	const computed = crypto
		.createHmac('sha256', secret)
		.update(rawBody)
		.digest('hex');
	return crypto.timingSafeEqual(
		Buffer.from(expected, 'hex'),
		Buffer.from(computed, 'hex'),
	);
}

// ---------------------------------------------------------------------------
// Key generation (for initial setup / agent creation)
// ---------------------------------------------------------------------------

export async function generateKeyPairs(): Promise<{
	signing: { privateKey: string; publicKey: string };
	encryption: { privateKey: string; publicKey: string };
}> {
	const crypto = require('crypto');
	const ed = await import('@noble/ed25519');

	// Ed25519 signing keypair
	const sigPrivBytes = ed.utils.randomPrivateKey();
	const sigPubBytes = await ed.getPublicKeyAsync(sigPrivBytes);

	// X25519 encryption keypair (Node.js native)
	const x25519 = crypto.generateKeyPairSync('x25519', {
		publicKeyEncoding: { type: 'spki', format: 'der' },
		privateKeyEncoding: { type: 'pkcs8', format: 'der' },
	});
	// Extract raw 32 bytes from DER
	// X25519 public DER = 12 byte header + 32 byte key
	const encPubRaw = x25519.publicKey.slice(-32);
	// X25519 private DER = 16 byte header + 32 byte key
	const encPrivRaw = x25519.privateKey.slice(-32);

	return {
		signing: {
			privateKey: b64urlEncode(sigPrivBytes),
			publicKey: b64urlEncode(sigPubBytes),
		},
		encryption: {
			privateKey: b64urlEncode(encPrivRaw),
			publicKey: b64urlEncode(encPubRaw),
		},
	};
}

// ---------------------------------------------------------------------------
// Auto-provisioning
// ---------------------------------------------------------------------------

export async function ensureProvisioned(
	ctx: RineContext,
	creds: RineCredentials,
): Promise<{ creds: ResolvedCredentials; provisioned: boolean }> {
	const baseUrl = resolveBaseUrl(creds);

	// 1. All key fields manually filled → use as-is
	if (creds.agentId && creds.signingPrivateKey && creds.encryptionPrivateKey) {
		return {
			creds: {
				baseUrl,
				clientId: creds.clientId,
				clientSecret: creds.clientSecret,
				agentId: creds.agentId,
				signingPrivateKey: creds.signingPrivateKey,
				signingPublicKey: creds.signingPublicKey || '',
				encryptionPrivateKey: creds.encryptionPrivateKey,
				encryptionPublicKey: creds.encryptionPublicKey || '',
				webhookSecret: creds.webhookSecret,
			},
			provisioned: false,
		};
	}

	// 2. Check keystore for existing entry
	const entry = getOrgEntry(creds.clientId);
	if (entry) {
		// Verify agent still exists (unauthenticated, cheap)
		try {
			await ctx.helpers.httpRequest({
				method: 'GET',
				url: `${baseUrl}/agents/${entry.agent_id}/keys`,
				json: true,
			});
			return {
				creds: {
					baseUrl,
					clientId: creds.clientId,
					clientSecret: creds.clientSecret,
					agentId: entry.agent_id,
					agentHandle: entry.agent_handle,
					signingPrivateKey: entry.signing_private_key,
					signingPublicKey: entry.signing_public_key,
					encryptionPrivateKey: entry.encryption_private_key,
					encryptionPublicKey: entry.encryption_public_key,
					webhookSecret: entry.webhook_secret || creds.webhookSecret,
				},
				provisioned: false,
			};
		} catch {
			// Agent revoked or gone — clear and re-provision
			clearOrgEntry(creds.clientId, entry.agent_id);
		}
	}

	// 3. Auto-provision
	const token = await getAccessToken(ctx, creds);
	const authHeaders: Record<string, string> = {
		Authorization: `Bearer ${token}`,
		'Content-Type': 'application/json',
	};

	// List existing agents
	const agentsResponse = await ctx.helpers.httpRequest({
		method: 'GET',
		url: `${baseUrl}/agents`,
		headers: { Authorization: `Bearer ${token}` },
		json: true,
	});
	const agents = Array.isArray(agentsResponse) ? agentsResponse
		: Array.isArray(agentsResponse?.items) ? agentsResponse.items
		: [];

	const keys = await generateKeyPairs();
	let agentId: string;
	let agentHandle: string | undefined;

	if (agents.length > 0) {
		// Existing agent — try to upload new keys
		const agent = agents[0];
		agentId = agent.id;
		agentHandle = agent.handle;
		try {
			await ctx.helpers.httpRequest({
				method: 'POST',
				url: `${baseUrl}/agents/${agentId}/keys`,
				headers: authHeaders,
				body: {
					signing_public_key: ed25519PubJwk(keys.signing.publicKey),
					encryption_public_key: x25519PubJwk(keys.encryption.publicKey),
				},
				json: true,
			});
		} catch {
			// Key upload failed — create a new agent instead
			const resp = await ctx.helpers.httpRequest({
				method: 'POST',
				url: `${baseUrl}/agents`,
				headers: authHeaders,
				body: {
					name: `n8n-${Date.now()}`,
					signing_public_key: ed25519PubJwk(keys.signing.publicKey),
					encryption_public_key: x25519PubJwk(keys.encryption.publicKey),
				},
				json: true,
			});
			agentId = resp.id;
			agentHandle = resp.handle;
		}
	} else {
		// No agents — create one
		const resp = await ctx.helpers.httpRequest({
			method: 'POST',
			url: `${baseUrl}/agents`,
			headers: authHeaders,
			body: {
				name: `n8n-${Date.now()}`,
				signing_public_key: ed25519PubJwk(keys.signing.publicKey),
				encryption_public_key: x25519PubJwk(keys.encryption.publicKey),
			},
			json: true,
		});
		agentId = resp.id;
		agentHandle = resp.handle;
	}

	// Save to keystore
	const newEntry: KeystoreEntry = {
		agent_id: agentId,
		agent_handle: agentHandle,
		signing_private_key: keys.signing.privateKey,
		signing_public_key: keys.signing.publicKey,
		encryption_private_key: keys.encryption.privateKey,
		encryption_public_key: keys.encryption.publicKey,
		provisioned_at: new Date().toISOString(),
	};
	const saved = saveOrgEntry(creds.clientId, newEntry);

	return {
		creds: {
			baseUrl,
			clientId: creds.clientId,
			clientSecret: creds.clientSecret,
			agentId,
			agentHandle,
			signingPrivateKey: keys.signing.privateKey,
			signingPublicKey: keys.signing.publicKey,
			encryptionPrivateKey: keys.encryption.privateKey,
			encryptionPublicKey: keys.encryption.publicKey,
			webhookSecret: creds.webhookSecret,
			...(!saved ? { _keystoreWriteFailed: true } as Record<string, unknown> : {}),
		},
		provisioned: true,
	};
}

// ---------------------------------------------------------------------------
// Fetch recipient public keys
// ---------------------------------------------------------------------------

export async function fetchRecipientKeys(
	ctx: IExecuteFunctions,
	creds: RineCredentials,
	agentId: string,
): Promise<{ signingPubKey: string; encryptionPubKey: string }> {
	const baseUrl = resolveBaseUrl(creds);
	const response = await ctx.helpers.httpRequest({
		method: 'GET',
		url: `${baseUrl}/agents/${agentId}/keys`,
		json: true,
	});

	return {
		signingPubKey: response.signing_public_key?.x ?? '',
		encryptionPubKey: response.encryption_public_key?.x ?? '',
	};
}

/**
 * Resolve a handle (agent@org.rine.network) to an agent UUID via WebFinger.
 */
export async function resolveHandle(
	ctx: IExecuteFunctions,
	creds: RineCredentials,
	handle: string,
): Promise<string> {
	const baseUrl = resolveBaseUrl(creds);
	const response = await ctx.helpers.httpRequest({
		method: 'GET',
		url: `${baseUrl}/.well-known/webfinger?resource=acct:${encodeURIComponent(handle)}`,
		json: true,
	});

	// Prefer aliases — first one matching /agents/{uuid} pattern
	if (Array.isArray(response.aliases)) {
		for (const alias of response.aliases) {
			const match = (alias as string).match(/\/agents\/([0-9a-fA-F-]{36})/);
			if (match) return match[1];
		}
	}

	// Fallback: self link, strip .json extension and extract UUID
	const selfLink = response.links?.find(
		(l: { rel: string; href: string }) => l.rel === 'self',
	);
	if (!selfLink?.href) {
		throw new Error(`Could not resolve handle: ${handle}`);
	}
	const parts = selfLink.href.split('/');
	const last = parts[parts.length - 1].replace(/\.json$/, '');
	return last;
}
