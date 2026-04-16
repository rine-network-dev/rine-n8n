import {
	IDataObject,
	IHookFunctions,
	IWebhookFunctions,
	IWebhookResponseData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';

import {
	RineCredentials,
	getAccessToken,
	verifyWebhookSignature,
	hpkeDecrypt,
	ensureProvisioned,
	getKeystorePath,
	updateOrgEntry,
} from './helpers';
import { getOrgEntry } from './keystore';

export class RineTrigger implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Rine Trigger',
		name: 'rineTrigger',
		icon: 'file:rine.png',
		group: ['trigger'],
		version: 1,
		subtitle: 'Receives rine messages via webhook',
		description: 'Triggers when a new message is received on rine.network. Verifies HMAC signature and decrypts E2EE payload.',
		defaults: {
			name: 'Rine Trigger',
		},
		inputs: [],
		outputs: ['main'],
		credentials: [
			{
				name: 'rineApi',
				required: true,
			},
		],
		webhooks: [
			{
				name: 'default',
				httpMethod: 'POST',
				responseMode: 'onReceived',
				path: 'rine',
			},
		],
		properties: [
			{
				displayName: 'Verify Signature',
				name: 'verifySignature',
				type: 'boolean',
				default: true,
				description: 'Whether to verify the HMAC-SHA256 webhook signature (recommended)',
			},
			{
				displayName: 'Auto-Fetch Full Message',
				name: 'autoFetch',
				type: 'boolean',
				default: true,
				description: 'Whether to automatically fetch the full message from rine (webhook only sends notification)',
			},
			{
				displayName: 'Auto-Decrypt',
				name: 'autoDecrypt',
				type: 'boolean',
				default: true,
				description: 'Whether to automatically decrypt the encrypted_payload',
			},
		],
	};

	webhookMethods = {
		default: {
			async checkExists(this: IHookFunctions): Promise<boolean> {
				const rawCreds = await this.getCredentials('rineApi') as unknown as RineCredentials;
				const entry = getOrgEntry(rawCreds.clientId);
				// If keystore has a webhook secret, assume webhook exists
				if (entry?.webhook_secret) return true;
				// If credentials have a webhook secret, also fine
				if (rawCreds.webhookSecret) return true;
				return false;
			},

			async create(this: IHookFunctions): Promise<boolean> {
				const rawCreds = await this.getCredentials('rineApi') as unknown as RineCredentials;
				const { creds } = await ensureProvisioned(this, rawCreds);

				// If webhook secret already available (from creds or keystore), skip creation
				if (creds.webhookSecret) return true;

				const webhookUrl = this.getNodeWebhookUrl('default');
				if (!webhookUrl) return true; // can't determine URL, skip

				const token = await getAccessToken(this, creds);

				// Check if a webhook already exists for our URL
				const existing = await this.helpers.httpRequest({
					method: 'GET',
					url: `${creds.baseUrl}/webhooks`,
					headers: { Authorization: `Bearer ${token}` },
					json: true,
				});
				const webhooks = Array.isArray(existing) ? existing
					: Array.isArray(existing?.items) ? existing.items
					: [];
				const match = webhooks.find((w: { url: string }) => w.url === webhookUrl);
				if (match) {
					// Webhook exists but we don't have the secret (shown only at creation).
					// Can't recover — user must delete and let us recreate.
					return true;
				}

				// Create webhook on rine
				const resp = await this.helpers.httpRequest({
					method: 'POST',
					url: `${creds.baseUrl}/webhooks`,
					headers: {
						Authorization: `Bearer ${token}`,
						'Content-Type': 'application/json',
					},
					body: {
						agent_id: creds.agentId,
						url: webhookUrl,
					},
					json: true,
				});

				// Save secret and webhook ID to keystore
				if (resp.secret) {
					updateOrgEntry(creds.clientId, {
						webhook_secret: resp.secret,
						webhook_id: resp.id,
					});
				}

				return true;
			},

			async delete(this: IHookFunctions): Promise<boolean> {
				// Don't auto-delete rine webhooks — they may be shared across workflows
				return true;
			},
		},
	};

	async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
		const rawCreds = await this.getCredentials('rineApi') as unknown as RineCredentials;
		const { creds, provisioned } = await ensureProvisioned(this, rawCreds);
		const req = this.getRequestObject();
		const body = req.body;

		// 1. Verify HMAC signature
		const verifySignature = this.getNodeParameter('verifySignature', true) as boolean;
		if (verifySignature) {
			const sigHeader = req.headers['x-rine-signature'] as string | undefined;
			if (!sigHeader) {
				throw new NodeOperationError(
					this.getNode(),
					'Missing X-Rine-Signature header — possible spoofed request',
				);
			}
			if (!creds.webhookSecret) {
				throw new NodeOperationError(
					this.getNode(),
					'Webhook secret not available. Create a webhook via Rine Trigger activation or set it in credentials.',
				);
			}

			const rawBody = typeof req.rawBody === 'string'
				? req.rawBody
				: JSON.stringify(body);

			const valid = verifyWebhookSignature(rawBody, sigHeader, creds.webhookSecret);
			if (!valid) {
				throw new NodeOperationError(
					this.getNode(),
					'Webhook signature verification failed — payload may have been tampered',
				);
			}
		}

		// 2. Webhook payload is a notification, not the full message.
		const webhookPayload = body as {
			message_id: string;
			agent_id: string;
			event: string;
			timestamp: string;
		};

		const outputData: IDataObject = {
			webhook: webhookPayload,
		};

		if (provisioned) {
			outputData._rine_provisioned = true;
			outputData._rine_agent_id = creds.agentId;
			outputData._rine_agent_handle = creds.agentHandle || null;
			outputData._rine_keystore = getKeystorePath();
		}

		// 3. Auto-fetch full message
		const autoFetch = this.getNodeParameter('autoFetch', true) as boolean;
		if (autoFetch && webhookPayload.message_id) {
			try {
				const token = await getAccessToken(this, creds);
				const fullMessage = await this.helpers.httpRequest({
					method: 'GET',
					url: `${creds.baseUrl}/messages/${webhookPayload.message_id}`,
					headers: { Authorization: `Bearer ${token}` },
					json: true,
				});

				outputData.message = fullMessage;

				// 4. Auto-decrypt
				const autoDecrypt = this.getNodeParameter('autoDecrypt', true) as boolean;
				if (
					autoDecrypt &&
					creds.encryptionPrivateKey &&
					fullMessage.encrypted_payload
				) {
					try {
						const plaintext = await hpkeDecrypt(
							fullMessage.encrypted_payload,
							creds.encryptionPrivateKey,
						);
						outputData.decrypted_payload = JSON.parse(plaintext);
					} catch (err) {
						outputData.decrypted_payload = null;
						outputData.decrypt_error = (err as Error).message;
					}
				}
			} catch (err) {
				outputData.fetch_error = (err as Error).message;
			}
		}

		return {
			workflowData: [this.helpers.returnJsonArray(outputData)],
		};
	}
}
