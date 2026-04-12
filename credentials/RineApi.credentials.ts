import {
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class RineApi implements ICredentialType {
	name = 'rineApi';
	displayName = 'Rine API';
	documentationUrl = 'https://rine.network/skill.md';

	properties: INodeProperties[] = [
		{
			displayName: 'Client ID',
			name: 'clientId',
			type: 'string',
			default: '',
			required: true,
			description: 'OAuth client_id from "rine onboard" or ~/.config/rine/credentials.json',
		},
		{
			displayName: 'Client Secret',
			name: 'clientSecret',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description: 'OAuth client_secret from "rine onboard" (shown only once at registration)',
		},
		{
			displayName: 'Advanced Settings',
			name: 'advanced',
			type: 'boolean',
			default: false,
			description: 'Show advanced settings. Not needed for most users — keys and agent are auto-provisioned.',
		},
		// --- Advanced fields (hidden by default) ---
		{
			displayName: 'Base URL',
			name: 'baseUrl',
			type: 'string',
			default: 'https://rine.network',
			description: 'Rine API base URL',
			displayOptions: { show: { advanced: [true] } },
		},
		{
			displayName: 'Agent ID',
			name: 'agentId',
			type: 'string',
			default: '',
			description: 'Agent UUID. Leave empty to auto-detect or auto-create.',
			displayOptions: { show: { advanced: [true] } },
		},
		{
			displayName: 'Signing Private Key (Ed25519, base64url)',
			name: 'signingPrivateKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description: 'Ed25519 private key for message signing. Leave empty for auto-provisioning.',
			displayOptions: { show: { advanced: [true] } },
		},
		{
			displayName: 'Signing Public Key (Ed25519, base64url)',
			name: 'signingPublicKey',
			type: 'string',
			default: '',
			description: 'Ed25519 public key. Leave empty for auto-provisioning.',
			displayOptions: { show: { advanced: [true] } },
		},
		{
			displayName: 'Encryption Private Key (X25519, base64url)',
			name: 'encryptionPrivateKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description: 'X25519 private key for HPKE decryption. Leave empty for auto-provisioning.',
			displayOptions: { show: { advanced: [true] } },
		},
		{
			displayName: 'Encryption Public Key (X25519, base64url)',
			name: 'encryptionPublicKey',
			type: 'string',
			default: '',
			description: 'X25519 public key for HPKE encryption. Leave empty for auto-provisioning.',
			displayOptions: { show: { advanced: [true] } },
		},
		{
			displayName: 'Webhook Secret',
			name: 'webhookSecret',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description: 'HMAC-SHA256 secret for webhook verification. Auto-created by Rine Trigger node.',
			displayOptions: { show: { advanced: [true] } },
		},
	];

	// n8n doesn't natively support OAuth client_credentials for "test",
	// so we do a manual token exchange in the test request.
	// The actual auth is handled in the node's helper methods.
	test: ICredentialTestRequest = {
		request: {
			method: 'POST',
			url: '={{$credentials.baseUrl || "https://rine.network"}}/oauth/token',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: '={{ "grant_type=client_credentials&client_id=" + $credentials.clientId + "&client_secret=" + $credentials.clientSecret }}',
		},
	};
}
