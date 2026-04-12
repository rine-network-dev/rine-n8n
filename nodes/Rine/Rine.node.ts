import {
	IExecuteFunctions,
	ILoadOptionsFunctions,
	INodeExecutionData,
	INodePropertyOptions,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';

import {
	RineCredentials,
	ResolvedCredentials,
	getAccessToken,
	hpkeEncrypt,
	hpkeDecrypt,
	fetchRecipientKeys,
	resolveHandle,
	generateKeyPairs,
	ed25519PubJwk,
	x25519PubJwk,
	ensureProvisioned,
	getKeystorePath,
	getAgentEntry,
} from './helpers';

import { saveOrgEntry, clearOrgEntry, KeystoreEntry } from './keystore';

// =======================================================================
// Handler functions
// =======================================================================

// Shared send logic — encrypts payload and sends to recipient
async function doSend(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	to: string,
	type: string,
	payload: object,
	metadata?: string,
): Promise<object> {
	let recipientAgentId: string;
	const isHandle = to.includes('@');
	if (isHandle) {
		recipientAgentId = await resolveHandle(ctx, creds, to);
	} else {
		recipientAgentId = to;
	}

	const recipientKeys = await fetchRecipientKeys(ctx, creds, recipientAgentId);
	if (!recipientKeys.encryptionPubKey) {
		throw new NodeOperationError(ctx.getNode(), `Recipient ${to} has no encryption public key`);
	}

	const encryptedPayload = await hpkeEncrypt(
		JSON.stringify(payload),
		recipientKeys.encryptionPubKey,
	);

	const body: Record<string, unknown> = {
		type,
		encrypted_payload: encryptedPayload,
		encryption_version: 'hpke-v1',
	};

	if (isHandle) {
		body.to_handle = to;
	} else {
		body.to_agent_id = to;
	}

	if (creds.signingPrivateKey && creds.signingPublicKey) {
		body.sender_signing_kid = `rine:${creds.agentId ?? 'unknown'}`;
	}

	if (metadata) {
		body.metadata = typeof metadata === 'string' ? JSON.parse(metadata) : metadata;
	}

	const headers: Record<string, string> = {
		Authorization: `Bearer ${token}`,
		'Content-Type': 'application/json',
	};
	if (creds.agentId) {
		headers['X-Rine-Agent'] = creds.agentId;
	}

	return ctx.helpers.httpRequest({
		method: 'POST',
		url: `${creds.baseUrl}/messages`,
		headers,
		body,
		json: true,
	});
}

async function messageSendDm(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const to = ctx.getNodeParameter('to', idx) as string;
	const text = ctx.getNodeParameter('messageText', idx) as string;
	const metadata = ctx.getNodeParameter('metadata', idx, '') as string;
	return doSend(ctx, creds, token, to, 'rine.v1.dm', { text }, metadata);
}

async function messageSendTaskRequest(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const to = ctx.getNodeParameter('to', idx) as string;
	const task = ctx.getNodeParameter('taskDescription', idx) as string;
	const priority = ctx.getNodeParameter('priority', idx) as string;
	const additionalDataRaw = ctx.getNodeParameter('additionalData', idx, '') as string;
	const metadata = ctx.getNodeParameter('metadata', idx, '') as string;

	const payload: Record<string, unknown> = { task, priority };
	if (additionalDataRaw) {
		payload.data = typeof additionalDataRaw === 'string' ? JSON.parse(additionalDataRaw) : additionalDataRaw;
	}
	return doSend(ctx, creds, token, to, 'rine.v1.task_request', payload, metadata);
}

async function messageSendTaskResponse(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const to = ctx.getNodeParameter('to', idx) as string;
	const result = ctx.getNodeParameter('resultText', idx) as string;
	const success = ctx.getNodeParameter('success', idx) as boolean;
	const additionalDataRaw = ctx.getNodeParameter('additionalData', idx, '') as string;
	const metadata = ctx.getNodeParameter('metadata', idx, '') as string;

	const payload: Record<string, unknown> = { result, success };
	if (additionalDataRaw) {
		payload.data = typeof additionalDataRaw === 'string' ? JSON.parse(additionalDataRaw) : additionalDataRaw;
	}
	return doSend(ctx, creds, token, to, 'rine.v1.task_response', payload, metadata);
}

async function messageSendStatusUpdate(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const to = ctx.getNodeParameter('to', idx) as string;
	const status = ctx.getNodeParameter('status', idx) as string;
	const progress = ctx.getNodeParameter('progress', idx, 0) as number;
	const details = ctx.getNodeParameter('statusDetails', idx, '') as string;
	const metadata = ctx.getNodeParameter('metadata', idx, '') as string;

	const payload: Record<string, unknown> = { status, progress };
	if (details) payload.details = details;
	return doSend(ctx, creds, token, to, 'rine.v1.status_update', payload, metadata);
}

async function messageSendCustom(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const to = ctx.getNodeParameter('to', idx) as string;
	const type = ctx.getNodeParameter('customType', idx) as string;
	const payloadRaw = ctx.getNodeParameter('payload', idx);
	const metadata = ctx.getNodeParameter('metadata', idx, '') as string;

	const payload = typeof payloadRaw === 'string' ? JSON.parse(payloadRaw) : payloadRaw;
	return doSend(ctx, creds, token, to, type, payload, metadata);
}

async function messageInbox(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const limit = ctx.getNodeParameter('limit', idx, 20) as number;
	const autoDecrypt = ctx.getNodeParameter('autoDecrypt', idx, true) as boolean;

	if (!creds.agentId) {
		throw new NodeOperationError(ctx.getNode(), 'Agent ID is required in credentials for inbox');
	}

	const response = await ctx.helpers.httpRequest({
		method: 'GET',
		url: `${creds.baseUrl}/agents/${creds.agentId}/messages`,
		headers: { Authorization: `Bearer ${token}` },
		qs: { limit },
		json: true,
	});

	if (autoDecrypt && creds.encryptionPrivateKey && response.items) {
		for (const msg of response.items) {
			if (msg.encrypted_payload) {
				try {
					const plaintext = await hpkeDecrypt(msg.encrypted_payload, creds.encryptionPrivateKey);
					msg.decrypted_payload = JSON.parse(plaintext);
				} catch (err) {
					msg.decrypted_payload = null;
					msg.decrypt_error = (err as Error).message;
				}
			}
		}
	}

	return response;
}

async function messageReply(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const messageId = ctx.getNodeParameter('messageId', idx) as string;
	const messageType = ctx.getNodeParameter('messageType', idx) as string;
	const type = messageType === 'custom'
		? ctx.getNodeParameter('replyCustomType', idx) as string
		: messageType;
	const payloadRaw = ctx.getNodeParameter('replyPayload', idx);
	const payload = typeof payloadRaw === 'string' ? JSON.parse(payloadRaw) : payloadRaw;

	// Fetch original message to get sender's agent ID
	const origMsg = await ctx.helpers.httpRequest({
		method: 'GET',
		url: `${creds.baseUrl}/messages/${messageId}`,
		headers: { Authorization: `Bearer ${token}` },
		json: true,
	});

	// Encrypt reply for the original sender
	const senderKeys = await fetchRecipientKeys(ctx, creds, origMsg.from_agent_id);
	const encryptedPayload = await hpkeEncrypt(
		JSON.stringify(payload),
		senderKeys.encryptionPubKey,
	);

	const body: Record<string, unknown> = {
		type,
		encrypted_payload: encryptedPayload,
		encryption_version: 'hpke-v1',
	};

	if (creds.signingPrivateKey) {
		body.sender_signing_kid = `rine:${creds.agentId ?? 'unknown'}`;
	}

	const headers: Record<string, string> = {
		Authorization: `Bearer ${token}`,
		'Content-Type': 'application/json',
	};
	if (creds.agentId) {
		headers['X-Rine-Agent'] = creds.agentId;
	}

	return ctx.helpers.httpRequest({
		method: 'POST',
		url: `${creds.baseUrl}/messages/${messageId}/reply`,
		headers,
		body,
		json: true,
	});
}

async function messageRead(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const messageId = ctx.getNodeParameter('messageId', idx) as string;
	const autoDecrypt = ctx.getNodeParameter('autoDecrypt', idx, true) as boolean;

	const msg = await ctx.helpers.httpRequest({
		method: 'GET',
		url: `${creds.baseUrl}/messages/${messageId}`,
		headers: { Authorization: `Bearer ${token}` },
		json: true,
	});

	if (autoDecrypt && creds.encryptionPrivateKey && msg.encrypted_payload) {
		try {
			const plaintext = await hpkeDecrypt(msg.encrypted_payload, creds.encryptionPrivateKey);
			msg.decrypted_payload = JSON.parse(plaintext);
		} catch (err) {
			msg.decrypted_payload = null;
			msg.decrypt_error = (err as Error).message;
		}
	}

	return msg;
}

async function messageDecrypt(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	idx: number,
): Promise<object> {
	const encPayload = ctx.getNodeParameter('encryptedPayload', idx) as string;
	if (!creds.encryptionPrivateKey) {
		throw new NodeOperationError(ctx.getNode(), 'Encryption private key not configured in credentials');
	}
	const plaintext = await hpkeDecrypt(encPayload, creds.encryptionPrivateKey);
	return { decrypted: JSON.parse(plaintext) };
}

// Helper: parse comma-separated string to trimmed array, filtering empties
function csvToArray(s: string): string[] {
	return s.split(',').map((x) => x.trim()).filter(Boolean);
}

// Helper: build card body from a bag of values
function buildCardBody(
	values: Record<string, unknown>,
	includeVersion: boolean,
): Record<string, unknown> | null {
	const description = (values.cardDescription ?? '') as string;
	const categories = (values.cardCategories ?? '') as string;
	const languages = (values.cardLanguages ?? '') as string;
	const pricing = (values.cardPricing ?? 'free') as string;
	const acceptTypes = (values.cardAcceptTypes ?? '') as string;
	const skillsRaw = (values.cardSkills ?? '') as string;
	const isPublic = (values.cardIsPublic ?? true) as boolean;

	const card: Record<string, unknown> = {};
	let hasContent = false;

	if (description) { card.description = description; hasContent = true; }
	if (categories) { card.categories = csvToArray(categories); hasContent = true; }
	if (languages) { card.languages = csvToArray(languages); hasContent = true; }
	if (pricing && pricing !== 'free') { card.pricing_model = pricing; hasContent = true; }
	if (acceptTypes) { card.accept_types = csvToArray(acceptTypes); hasContent = true; }
	if (skillsRaw) {
		card.skills = typeof skillsRaw === 'string' ? JSON.parse(skillsRaw) : skillsRaw;
		hasContent = true;
	}
	card.is_public = isPublic;

	if (includeVersion) {
		const version = (values.cardVersion ?? '') as string;
		if (version) card.version = version;
	}

	return hasContent ? card : null;
}

async function agentCreate(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const name = ctx.getNodeParameter('agentName', idx) as string;
	const options = ctx.getNodeParameter('createOptions', idx, {}) as Record<string, unknown>;
	const humanOversight = (options.humanOversight ?? true) as boolean;
	const unlisted = (options.unlisted ?? false) as boolean;
	const keys = await generateKeyPairs();

	const createBody: Record<string, unknown> = {
		name,
		signing_public_key: ed25519PubJwk(keys.signing.publicKey),
		encryption_public_key: x25519PubJwk(keys.encryption.publicKey),
		human_oversight: humanOversight,
		unlisted,
	};

	const response = await ctx.helpers.httpRequest({
		method: 'POST',
		url: `${creds.baseUrl}/agents`,
		headers: {
			Authorization: `Bearer ${token}`,
			'Content-Type': 'application/json',
		},
		body: createBody,
		json: true,
	});

	// Save keys to keystore
	const keystoreEntry: KeystoreEntry = {
		agent_id: response.id,
		agent_handle: response.handle,
		signing_private_key: keys.signing.privateKey,
		signing_public_key: keys.signing.publicKey,
		encryption_private_key: keys.encryption.privateKey,
		encryption_public_key: keys.encryption.publicKey,
		provisioned_at: new Date().toISOString(),
	};
	saveOrgEntry(creds.clientId, keystoreEntry);

	// If card fields are filled, update the card right after creation
	const cardBody = buildCardBody(options, false);
	let cardResult: object | undefined;
	if (cardBody && response.handle) {
		cardBody.name = name;
		cardResult = await ctx.helpers.httpRequest({
			method: 'PUT',
			url: `${creds.baseUrl}/agents/${response.handle}/card`,
			headers: {
				Authorization: `Bearer ${token}`,
				'Content-Type': 'application/json',
			},
			body: cardBody,
			json: true,
		});
	}

	return {
		...response,
		_card: cardResult || null,
		_keys: {
			message: 'Keys saved to keystore automatically. You can select this agent from the Agent dropdown.',
			signing_private_key: keys.signing.privateKey,
			signing_public_key: keys.signing.publicKey,
			encryption_private_key: keys.encryption.privateKey,
			encryption_public_key: keys.encryption.publicKey,
		},
	};
}

async function agentList(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
): Promise<object> {
	return ctx.helpers.httpRequest({
		method: 'GET',
		url: `${creds.baseUrl}/agents`,
		headers: { Authorization: `Bearer ${token}` },
		json: true,
	});
}

async function agentGenerateKeys(): Promise<object> {
	const keys = await generateKeyPairs();
	return {
		message: 'Keys generated. Copy these into your Rine credential configuration.',
		signing: {
			privateKey: keys.signing.privateKey,
			publicKey: keys.signing.publicKey,
			publicKeyJwk: ed25519PubJwk(keys.signing.publicKey),
		},
		encryption: {
			privateKey: keys.encryption.privateKey,
			publicKey: keys.encryption.publicKey,
			publicKeyJwk: x25519PubJwk(keys.encryption.publicKey),
		},
	};
}

async function agentDelete(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const agentId = ctx.getNodeParameter('targetAgentId', idx) as string;
	const deleteWebhooks = ctx.getNodeParameter('deleteWebhooks', idx, true) as boolean;

	const deletedWebhooks: string[] = [];

	// 1. Delete associated webhooks if requested
	if (deleteWebhooks) {
		const webhooksResponse = await ctx.helpers.httpRequest({
			method: 'GET',
			url: `${creds.baseUrl}/webhooks`,
			headers: { Authorization: `Bearer ${token}` },
			json: true,
		});
		const webhooks = Array.isArray(webhooksResponse) ? webhooksResponse
			: Array.isArray(webhooksResponse?.items) ? webhooksResponse.items
			: [];

		for (const wh of webhooks) {
			if (wh.agent_id === agentId) {
				try {
					await ctx.helpers.httpRequest({
						method: 'DELETE',
						url: `${creds.baseUrl}/webhooks/${wh.id}`,
						headers: { Authorization: `Bearer ${token}` },
					});
					deletedWebhooks.push(wh.id);
				} catch {
					// Webhook may already be gone, continue
				}
			}
		}
	}

	// 2. Delete the agent
	await ctx.helpers.httpRequest({
		method: 'DELETE',
		url: `${creds.baseUrl}/agents/${agentId}`,
		headers: { Authorization: `Bearer ${token}` },
	});

	// 3. Clean up keystore
	clearOrgEntry(creds.clientId, agentId);

	return {
		ok: true,
		deleted_agent: agentId,
		deleted_webhooks: deletedWebhooks,
	};
}

async function agentUpdate(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const agentId = ctx.getNodeParameter('targetAgentId', idx) as string;
	const humanOversight = ctx.getNodeParameter('updateHumanOversight', idx, '') as string;
	const incomingPolicy = ctx.getNodeParameter('updateIncomingPolicy', idx, '') as string;
	const outgoingPolicy = ctx.getNodeParameter('updateOutgoingPolicy', idx, '') as string;

	const body: Record<string, unknown> = {};
	if (humanOversight) body.human_oversight = humanOversight === 'true';
	if (incomingPolicy) body.incoming_policy = incomingPolicy;
	if (outgoingPolicy) body.outgoing_policy = outgoingPolicy;

	if (Object.keys(body).length === 0) {
		throw new NodeOperationError(ctx.getNode(), 'No fields to update — select at least one setting to change');
	}

	return ctx.helpers.httpRequest({
		method: 'PUT',
		url: `${creds.baseUrl}/agents/${agentId}`,
		headers: {
			Authorization: `Bearer ${token}`,
			'Content-Type': 'application/json',
		},
		body,
		json: true,
	});
}

async function agentUpdateCard(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const agentId = ctx.getNodeParameter('targetAgentId', idx) as string;

	// We need the agent's handle for the card endpoint — fetch it
	const agentsResponse = await ctx.helpers.httpRequest({
		method: 'GET',
		url: `${creds.baseUrl}/agents`,
		headers: { Authorization: `Bearer ${token}` },
		json: true,
	});
	const agents = Array.isArray(agentsResponse) ? agentsResponse
		: Array.isArray(agentsResponse?.items) ? agentsResponse.items
		: [];
	const agent = agents.find((a: { id: string }) => a.id === agentId);
	if (!agent?.handle) {
		throw new NodeOperationError(ctx.getNode(), `Could not find handle for agent ${agentId}`);
	}

	const cardValues: Record<string, unknown> = {
		cardDescription: ctx.getNodeParameter('cardDescription', idx, '') as string,
		cardCategories: ctx.getNodeParameter('cardCategories', idx, '') as string,
		cardLanguages: ctx.getNodeParameter('cardLanguages', idx, '') as string,
		cardPricing: ctx.getNodeParameter('cardPricing', idx, 'free') as string,
		cardAcceptTypes: ctx.getNodeParameter('cardAcceptTypes', idx, '') as string,
		cardSkills: ctx.getNodeParameter('cardSkills', idx, '') as string,
		cardIsPublic: ctx.getNodeParameter('cardIsPublic', idx, true) as boolean,
		cardVersion: ctx.getNodeParameter('cardVersion', idx, '') as string,
	};
	const cardBody = buildCardBody(cardValues, true);
	if (!cardBody) {
		throw new NodeOperationError(ctx.getNode(), 'No card fields to update — fill in at least one field');
	}

	return ctx.helpers.httpRequest({
		method: 'PUT',
		url: `${creds.baseUrl}/agents/${agent.handle}/card`,
		headers: {
			Authorization: `Bearer ${token}`,
			'Content-Type': 'application/json',
		},
		body: cardBody,
		json: true,
	});
}

async function webhookCreate(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const url = ctx.getNodeParameter('webhookUrl', idx) as string;
	if (!creds.agentId) {
		throw new NodeOperationError(ctx.getNode(), 'Agent ID required in credentials to create webhook');
	}

	const response = await ctx.helpers.httpRequest({
		method: 'POST',
		url: `${creds.baseUrl}/webhooks`,
		headers: {
			Authorization: `Bearer ${token}`,
			'Content-Type': 'application/json',
		},
		body: { agent_id: creds.agentId, url },
		json: true,
	});

	return {
		...response,
		_note: 'Save the "secret" in your Rine credentials as Webhook Secret. Shown only once.',
	};
}

async function webhookList(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
): Promise<object> {
	return ctx.helpers.httpRequest({
		method: 'GET',
		url: `${creds.baseUrl}/webhooks`,
		headers: { Authorization: `Bearer ${token}` },
		json: true,
	});
}

async function webhookDelete(
	ctx: IExecuteFunctions,
	creds: ResolvedCredentials,
	token: string,
	idx: number,
): Promise<object> {
	const webhookId = ctx.getNodeParameter('webhookId', idx) as string;
	await ctx.helpers.httpRequest({
		method: 'DELETE',
		url: `${creds.baseUrl}/webhooks/${webhookId}`,
		headers: { Authorization: `Bearer ${token}` },
	});
	return { ok: true, deleted: webhookId };
}

// =======================================================================
// Node class
// =======================================================================

export class Rine implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Rine',
		name: 'rine',
		icon: 'file:rine.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
		description: 'Send and receive E2EE messages on rine.network',
		defaults: { name: 'Rine' },
		inputs: ['main'],
		outputs: ['main'],
		credentials: [{ name: 'rineApi', required: true }],
		properties: [
			// --- Resource ---
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{ name: 'Message', value: 'message' },
					{ name: 'Agent', value: 'agent' },
					{ name: 'Webhook', value: 'webhook' },
				],
				default: 'message',
			},

			// --- Agent selector (dynamic, loaded from API) ---
			{
				displayName: 'Agent',
				name: 'agentId',
				type: 'options',
				typeOptions: {
					loadOptionsMethod: 'getAgents',
				},
				default: '',
				description: 'Agent to use for this operation. Leave empty to use the auto-provisioned agent.',
				displayOptions: {
					show: {
						resource: ['message', 'webhook'],
					},
				},
			},

			// === MESSAGE ===
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['message'] } },
				options: [
					{ name: 'Send Direct Message', value: 'sendDm', action: 'Send a direct message' },
					{ name: 'Send Task Request', value: 'sendTaskRequest', action: 'Send a task request' },
					{ name: 'Send Task Response', value: 'sendTaskResponse', action: 'Send a task response' },
					{ name: 'Send Status Update', value: 'sendStatusUpdate', action: 'Send a status update' },
					{ name: 'Send Custom Message', value: 'sendCustom', action: 'Send a custom message' },
					{ name: 'Inbox', value: 'inbox', action: 'Read inbox' },
					{ name: 'Reply', value: 'reply', action: 'Reply to a message' },
					{ name: 'Read', value: 'read', action: 'Read a message' },
					{ name: 'Decrypt', value: 'decrypt', action: 'Decrypt a payload' },
				],
				default: 'sendDm',
			},

			// --- Shared "To" field for all send operations ---
			{
				displayName: 'To',
				name: 'to',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { resource: ['message'], operation: ['sendDm', 'sendTaskRequest', 'sendTaskResponse', 'sendStatusUpdate', 'sendCustom'] } },
				placeholder: 'agent@org.rine.network',
				description: 'Recipient handle (e.g. agent@org.rine.network) or agent UUID',
			},

			// --- Send Direct Message ---
			{
				displayName: 'Message',
				name: 'messageText',
				type: 'string',
				typeOptions: { rows: 4 },
				default: '',
				required: true,
				displayOptions: { show: { resource: ['message'], operation: ['sendDm'] } },
				description: 'Text message to send',
			},

			// --- Send Task Request ---
			{
				displayName: 'Task Description',
				name: 'taskDescription',
				type: 'string',
				typeOptions: { rows: 4 },
				default: '',
				required: true,
				displayOptions: { show: { resource: ['message'], operation: ['sendTaskRequest'] } },
				description: 'What you are asking the recipient to do',
			},
			{
				displayName: 'Priority',
				name: 'priority',
				type: 'options',
				options: [
					{ name: 'Low', value: 'low' },
					{ name: 'Normal', value: 'normal' },
					{ name: 'High', value: 'high' },
					{ name: 'Urgent', value: 'urgent' },
				],
				default: 'normal',
				displayOptions: { show: { resource: ['message'], operation: ['sendTaskRequest'] } },
			},
			{
				displayName: 'Additional Data (JSON)',
				name: 'additionalData',
				type: 'json',
				default: '',
				displayOptions: { show: { resource: ['message'], operation: ['sendTaskRequest'] } },
				description: 'Optional extra structured data to include with the request',
			},

			// --- Send Task Response ---
			{
				displayName: 'Result',
				name: 'resultText',
				type: 'string',
				typeOptions: { rows: 4 },
				default: '',
				required: true,
				displayOptions: { show: { resource: ['message'], operation: ['sendTaskResponse'] } },
				description: 'The result or output of the completed task',
			},
			{
				displayName: 'Success',
				name: 'success',
				type: 'boolean',
				default: true,
				displayOptions: { show: { resource: ['message'], operation: ['sendTaskResponse'] } },
				description: 'Whether the task completed successfully',
			},
			{
				displayName: 'Additional Data (JSON)',
				name: 'additionalData',
				type: 'json',
				default: '',
				displayOptions: { show: { resource: ['message'], operation: ['sendTaskResponse'] } },
				description: 'Optional extra structured data to include with the response',
			},

			// --- Send Status Update ---
			{
				displayName: 'Status',
				name: 'status',
				type: 'options',
				options: [
					{ name: 'Queued', value: 'queued' },
					{ name: 'In Progress', value: 'in_progress' },
					{ name: 'Completed', value: 'completed' },
					{ name: 'Failed', value: 'failed' },
					{ name: 'Cancelled', value: 'cancelled' },
				],
				default: 'in_progress',
				required: true,
				displayOptions: { show: { resource: ['message'], operation: ['sendStatusUpdate'] } },
			},
			{
				displayName: 'Progress (%)',
				name: 'progress',
				type: 'number',
				typeOptions: { minValue: 0, maxValue: 100 },
				default: 0,
				displayOptions: { show: { resource: ['message'], operation: ['sendStatusUpdate'] } },
				description: 'Progress percentage (0-100)',
			},
			{
				displayName: 'Details',
				name: 'statusDetails',
				type: 'string',
				typeOptions: { rows: 2 },
				default: '',
				displayOptions: { show: { resource: ['message'], operation: ['sendStatusUpdate'] } },
				description: 'Optional details about the current status',
			},

			// --- Send Custom Message ---
			{
				displayName: 'Message Type',
				name: 'customType',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { resource: ['message'], operation: ['sendCustom'] } },
				placeholder: 'com.acme.v1.invoice',
				description: 'Custom message type (3+ dot-separated segments)',
			},
			{
				displayName: 'Payload (JSON)',
				name: 'payload',
				type: 'json',
				default: '{}',
				required: true,
				displayOptions: { show: { resource: ['message'], operation: ['sendCustom'] } },
				description: 'Message payload as JSON — will be encrypted before sending',
			},

			// --- Shared metadata for all send operations ---
			{
				displayName: 'Metadata (JSON)',
				name: 'metadata',
				type: 'json',
				default: '',
				displayOptions: { show: { resource: ['message'], operation: ['sendDm', 'sendTaskRequest', 'sendTaskResponse', 'sendStatusUpdate', 'sendCustom'] } },
				description: 'Optional metadata (max 4KB). Sent unencrypted — use for routing or tracking, not sensitive data.',
			},

			// --- Reply ---
			{
				displayName: 'Message ID',
				name: 'messageId',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { resource: ['message'], operation: ['reply', 'read'] } },
				description: 'ID of the message to reply to or read',
			},
			{
				displayName: 'Message Type',
				name: 'messageType',
				type: 'options',
				displayOptions: { show: { resource: ['message'], operation: ['reply'] } },
				options: [
					{ name: 'Direct Message', value: 'rine.v1.dm' },
					{ name: 'Task Request', value: 'rine.v1.task_request' },
					{ name: 'Task Response', value: 'rine.v1.task_response' },
					{ name: 'Status Update', value: 'rine.v1.status_update' },
					{ name: 'Custom', value: 'custom' },
				],
				default: 'rine.v1.task_response',
			},
			{
				displayName: 'Custom Type',
				name: 'replyCustomType',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['message'], operation: ['reply'], messageType: ['custom'] } },
				placeholder: 'com.acme.v1.invoice',
			},
			{
				displayName: 'Payload (JSON)',
				name: 'replyPayload',
				type: 'json',
				default: '{}',
				required: true,
				displayOptions: { show: { resource: ['message'], operation: ['reply'] } },
				description: 'Reply payload as JSON — will be encrypted before sending',
			},

			// --- Inbox / Read / Decrypt ---
			{
				displayName: 'Limit',
				name: 'limit',
				type: 'number',
				default: 20,
				displayOptions: { show: { resource: ['message'], operation: ['inbox'] } },
			},
			{
				displayName: 'Auto-Decrypt',
				name: 'autoDecrypt',
				type: 'boolean',
				default: true,
				displayOptions: { show: { resource: ['message'], operation: ['inbox', 'read'] } },
			},
			{
				displayName: 'Encrypted Payload (base64url)',
				name: 'encryptedPayload',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { resource: ['message'], operation: ['decrypt'] } },
			},

			// === AGENT ===
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['agent'] } },
				options: [
					{ name: 'Create', value: 'create', action: 'Create an agent' },
					{ name: 'Delete', value: 'delete', action: 'Delete an agent' },
					{ name: 'List', value: 'list', action: 'List agents' },
					{ name: 'Update', value: 'update', action: 'Update agent settings' },
					{ name: 'Update Card', value: 'updateCard', action: 'Update agent profile card' },
					{ name: 'Generate Keys', value: 'generateKeys', action: 'Generate E2EE keys' },
				],
				default: 'create',
			},

			// --- Agent selector for delete/update/updateCard ---
			{
				displayName: 'Agent',
				name: 'targetAgentId',
				type: 'options',
				typeOptions: {
					loadOptionsMethod: 'getAgents',
				},
				default: '',
				required: true,
				displayOptions: { show: { resource: ['agent'], operation: ['delete', 'update', 'updateCard'] } },
				description: 'Agent to operate on',
			},

			// --- Create fields ---
			{
				displayName: 'Agent Name',
				name: 'agentName',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { resource: ['agent'], operation: ['create'] } },
				placeholder: 'my-agent',
				description: 'Lowercase alphanumeric + hyphens. Becomes name@org.rine.network',
			},
			{
				displayName: 'Options',
				name: 'createOptions',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				displayOptions: { show: { resource: ['agent'], operation: ['create'] } },
				options: [
					{
						displayName: 'Human Oversight',
						name: 'humanOversight',
						type: 'boolean',
						default: true,
						description: 'Whether the agent requires human oversight before sending',
					},
					{
						displayName: 'Unlisted',
						name: 'unlisted',
						type: 'boolean',
						default: false,
						description: 'Whether to exclude the agent from the public directory',
					},
					{
						displayName: 'Description',
						name: 'cardDescription',
						type: 'string',
						typeOptions: { rows: 4 },
						default: '',
						description: 'Agent capability summary (max 5000 chars)',
					},
					{
						displayName: 'Categories',
						name: 'cardCategories',
						type: 'string',
						default: '',
						placeholder: 'legal, finance, devops',
						description: 'Comma-separated domain tags',
					},
					{
						displayName: 'Languages',
						name: 'cardLanguages',
						type: 'string',
						default: '',
						placeholder: 'en, it, de',
						description: 'Comma-separated ISO 639-1 language codes',
					},
					{
						displayName: 'Pricing Model',
						name: 'cardPricing',
						type: 'options',
						options: [
							{ name: 'Free', value: 'free' },
							{ name: 'Per Request', value: 'per_request' },
							{ name: 'Subscription', value: 'subscription' },
							{ name: 'Negotiated', value: 'negotiated' },
						],
						default: 'free',
					},
					{
						displayName: 'Accept Types',
						name: 'cardAcceptTypes',
						type: 'string',
						default: '',
						placeholder: 'rine.v1.dm, rine.v1.task_request',
						description: 'Comma-separated message types this agent accepts',
					},
					{
						displayName: 'Skills (JSON)',
						name: 'cardSkills',
						type: 'json',
						default: '',
						placeholder: '[{"id":"s1","name":"translate","description":"Translates text","tags":["nlp"]}]',
						description: 'Array of skill objects: {id, name, description, tags[]}',
					},
					{
						displayName: 'Public',
						name: 'cardIsPublic',
						type: 'boolean',
						default: true,
						description: 'Whether the agent card is visible in the public directory',
					},
				],
			},

			// --- Update Card fields (shown directly, not in options) ---
			{
				displayName: 'Description',
				name: 'cardDescription',
				type: 'string',
				typeOptions: { rows: 4 },
				default: '',
				displayOptions: { show: { resource: ['agent'], operation: ['updateCard'] } },
				description: 'Agent capability summary (max 5000 chars)',
			},
			{
				displayName: 'Categories',
				name: 'cardCategories',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['agent'], operation: ['updateCard'] } },
				placeholder: 'legal, finance, devops',
				description: 'Comma-separated domain tags',
			},
			{
				displayName: 'Languages',
				name: 'cardLanguages',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['agent'], operation: ['updateCard'] } },
				placeholder: 'en, it, de',
				description: 'Comma-separated ISO 639-1 language codes',
			},
			{
				displayName: 'Pricing Model',
				name: 'cardPricing',
				type: 'options',
				options: [
					{ name: 'Free', value: 'free' },
					{ name: 'Per Request', value: 'per_request' },
					{ name: 'Subscription', value: 'subscription' },
					{ name: 'Negotiated', value: 'negotiated' },
				],
				default: 'free',
				displayOptions: { show: { resource: ['agent'], operation: ['updateCard'] } },
			},
			{
				displayName: 'Accept Types',
				name: 'cardAcceptTypes',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['agent'], operation: ['updateCard'] } },
				placeholder: 'rine.v1.dm, rine.v1.task_request',
				description: 'Comma-separated message types this agent accepts',
			},
			{
				displayName: 'Skills (JSON)',
				name: 'cardSkills',
				type: 'json',
				default: '',
				displayOptions: { show: { resource: ['agent'], operation: ['updateCard'] } },
				placeholder: '[{"id":"s1","name":"translate","description":"Translates text","tags":["nlp"]}]',
				description: 'Array of skill objects: {id, name, description, tags[]}',
			},
			{
				displayName: 'Public',
				name: 'cardIsPublic',
				type: 'boolean',
				default: true,
				displayOptions: { show: { resource: ['agent'], operation: ['updateCard'] } },
				description: 'Whether the agent card is visible in the public directory',
			},
			{
				displayName: 'Card Version',
				name: 'cardVersion',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['agent'], operation: ['updateCard'] } },
				placeholder: '1.0.0',
				description: 'Semantic version for card tracking',
			},

			// --- Delete fields ---
			{
				displayName: 'Delete Webhooks',
				name: 'deleteWebhooks',
				type: 'boolean',
				default: true,
				displayOptions: { show: { resource: ['agent'], operation: ['delete'] } },
				description: 'Whether to also delete all webhooks associated with this agent',
			},

			// --- Update fields ---
			{
				displayName: 'Human Oversight',
				name: 'updateHumanOversight',
				type: 'options',
				options: [
					{ name: 'Don\'t Change', value: '' },
					{ name: 'Enabled', value: 'true' },
					{ name: 'Disabled', value: 'false' },
				],
				default: '',
				displayOptions: { show: { resource: ['agent'], operation: ['update'] } },
				description: 'Whether the agent requires human oversight',
			},
			{
				displayName: 'Incoming Policy',
				name: 'updateIncomingPolicy',
				type: 'options',
				options: [
					{ name: 'Don\'t Change', value: '' },
					{ name: 'Accept All', value: 'accept_all' },
					{ name: 'Groups Only', value: 'groups_only' },
				],
				default: '',
				displayOptions: { show: { resource: ['agent'], operation: ['update'] } },
				description: 'Restrict inbound message sources',
			},
			{
				displayName: 'Outgoing Policy',
				name: 'updateOutgoingPolicy',
				type: 'options',
				options: [
					{ name: 'Don\'t Change', value: '' },
					{ name: 'Send All', value: 'send_all' },
					{ name: 'Groups Only', value: 'groups_only' },
				],
				default: '',
				displayOptions: { show: { resource: ['agent'], operation: ['update'] } },
				description: 'Restrict outbound message destinations',
			},

			// === WEBHOOK ===
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['webhook'] } },
				options: [
					{ name: 'Create', value: 'create', action: 'Create a webhook' },
					{ name: 'List', value: 'list', action: 'List webhooks' },
					{ name: 'Delete', value: 'delete', action: 'Delete a webhook' },
				],
				default: 'create',
			},
			{
				displayName: 'Webhook URL',
				name: 'webhookUrl',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { resource: ['webhook'], operation: ['create'] } },
				placeholder: 'https://your-n8n.example.com/webhook/rine',
			},
			{
				displayName: 'Webhook ID',
				name: 'webhookId',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { resource: ['webhook'], operation: ['delete'] } },
			},
		],
	};

	methods = {
		loadOptions: {
			async getAgents(this: ILoadOptionsFunctions): Promise<INodePropertyOptions[]> {
				const creds = await this.getCredentials('rineApi') as unknown as RineCredentials;
				const baseUrl = creds.baseUrl || 'https://rine.network';
				const tokenResponse = await this.helpers.httpRequest({
					method: 'POST',
					url: `${baseUrl}/oauth/token`,
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: `grant_type=client_credentials&client_id=${encodeURIComponent(creds.clientId)}&client_secret=${encodeURIComponent(creds.clientSecret)}`,
					json: true,
				});
				const token = tokenResponse.access_token;
				const agentsResponse = await this.helpers.httpRequest({
					method: 'GET',
					url: `${baseUrl}/agents`,
					headers: { Authorization: `Bearer ${token}` },
					json: true,
				});
				const agents = Array.isArray(agentsResponse) ? agentsResponse
					: Array.isArray(agentsResponse?.items) ? agentsResponse.items
					: [];
				return agents.map((agent: { id: string; name?: string; handle?: string }) => ({
					name: agent.handle || agent.name || agent.id,
					value: agent.id,
					description: agent.handle ? `${agent.name || ''} (${agent.handle})`.trim() : agent.id,
				}));
			},
		},
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const rawCreds = await this.getCredentials('rineApi') as unknown as RineCredentials;
		const resource = this.getNodeParameter('resource', 0) as string;
		const operation = this.getNodeParameter('operation', 0) as string;

		const { creds, provisioned } = await ensureProvisioned(this, rawCreds);

		// Override agent ID and keys if the user selected a different agent
		if (resource === 'message' || resource === 'webhook') {
			const selectedAgent = this.getNodeParameter('agentId', 0, '') as string;
			if (selectedAgent && selectedAgent !== creds.agentId) {
				creds.agentId = selectedAgent;
				// Try to load keys for this agent from the keystore
				const agentEntry = getAgentEntry(creds.clientId, selectedAgent);
				if (agentEntry) {
					creds.signingPrivateKey = agentEntry.signing_private_key;
					creds.signingPublicKey = agentEntry.signing_public_key;
					creds.encryptionPrivateKey = agentEntry.encryption_private_key;
					creds.encryptionPublicKey = agentEntry.encryption_public_key;
					if (agentEntry.webhook_secret) {
						creds.webhookSecret = agentEntry.webhook_secret;
					}
				}
			}
		}

		if (provisioned) {
			returnData.push({
				json: {
					_rine_provisioned: true,
					_rine_agent_id: creds.agentId,
					_rine_agent_handle: creds.agentHandle || null,
					_rine_keystore: getKeystorePath(),
					_rine_note: 'Agent auto-provisioned. Keys saved to keystore. To use explicit credentials instead, fill in all key fields in the Rine credential.',
				},
			});
		}

		for (let i = 0; i < items.length; i++) {
			try {
				let result: object;

				if (resource === 'message') {
					const token = await getAccessToken(this, creds);
					switch (operation) {
						case 'sendDm': result = await messageSendDm(this, creds, token, i); break;
						case 'sendTaskRequest': result = await messageSendTaskRequest(this, creds, token, i); break;
						case 'sendTaskResponse': result = await messageSendTaskResponse(this, creds, token, i); break;
						case 'sendStatusUpdate': result = await messageSendStatusUpdate(this, creds, token, i); break;
						case 'sendCustom': result = await messageSendCustom(this, creds, token, i); break;
						case 'inbox': result = await messageInbox(this, creds, token, i); break;
						case 'reply': result = await messageReply(this, creds, token, i); break;
						case 'read': result = await messageRead(this, creds, token, i); break;
						case 'decrypt': result = await messageDecrypt(this, creds, i); break;
						default: throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
					}
				} else if (resource === 'agent') {
					switch (operation) {
						case 'create': result = await agentCreate(this, creds, await getAccessToken(this, creds), i); break;
						case 'delete': result = await agentDelete(this, creds, await getAccessToken(this, creds), i); break;
						case 'update': result = await agentUpdate(this, creds, await getAccessToken(this, creds), i); break;
						case 'updateCard': result = await agentUpdateCard(this, creds, await getAccessToken(this, creds), i); break;
						case 'list': result = await agentList(this, creds, await getAccessToken(this, creds)); break;
						case 'generateKeys': result = await agentGenerateKeys(); break;
						default: throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
					}
				} else if (resource === 'webhook') {
					const token = await getAccessToken(this, creds);
					switch (operation) {
						case 'create': result = await webhookCreate(this, creds, token, i); break;
						case 'list': result = await webhookList(this, creds, token); break;
						case 'delete': result = await webhookDelete(this, creds, token, i); break;
						default: throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
					}
				} else {
					throw new NodeOperationError(this.getNode(), `Unknown resource: ${resource}`);
				}

				returnData.push({ json: result as INodeExecutionData['json'] });
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({ json: { error: (error as Error).message }, pairedItem: { item: i } });
					continue;
				}
				throw error;
			}
		}

		return [returnData];
	}
}
