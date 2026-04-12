import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export interface KeystoreEntry {
	agent_id: string;
	agent_handle?: string;
	signing_private_key: string;
	signing_public_key: string;
	encryption_private_key: string;
	encryption_public_key: string;
	webhook_secret?: string;
	webhook_id?: string;
	provisioned_at: string;
}

interface OrgData {
	default_agent_id: string;
	agents: Record<string, KeystoreEntry>;
}

interface KeystoreData {
	orgs: Record<string, OrgData>;
}

export function getKeystorePath(): string {
	return process.env.RINE_KEYSTORE_PATH || path.join(os.homedir(), '.n8n', 'rine-keys.json');
}

function migrateIfNeeded(raw: Record<string, unknown>): KeystoreData {
	if (!raw || typeof raw.orgs !== 'object') return { orgs: {} };

	const orgs = raw.orgs as Record<string, unknown>;
	const result: KeystoreData = { orgs: {} };

	for (const [clientId, value] of Object.entries(orgs)) {
		if (!value || typeof value !== 'object') continue;
		const v = value as Record<string, unknown>;

		// New format: has 'agents' key
		if (v.agents && typeof v.agents === 'object') {
			result.orgs[clientId] = v as unknown as OrgData;
			continue;
		}

		// Legacy format: value is a flat KeystoreEntry (has agent_id at top level)
		if (typeof v.agent_id === 'string') {
			const entry = v as unknown as KeystoreEntry;
			result.orgs[clientId] = {
				default_agent_id: entry.agent_id,
				agents: { [entry.agent_id]: entry },
			};
		}
	}

	return result;
}

function readKeystore(): KeystoreData {
	try {
		const raw = fs.readFileSync(getKeystorePath(), 'utf-8');
		const data = JSON.parse(raw);
		return migrateIfNeeded(data);
	} catch {
		// File missing, corrupted, or unreadable
	}
	return { orgs: {} };
}

function writeKeystore(data: KeystoreData): boolean {
	try {
		const p = getKeystorePath();
		fs.mkdirSync(path.dirname(p), { recursive: true });
		fs.writeFileSync(p, JSON.stringify(data, null, 2), { mode: 0o600 });
		return true;
	} catch {
		return false;
	}
}

/** Get the default agent entry for an org (backward compatible) */
export function getOrgEntry(clientId: string): KeystoreEntry | undefined {
	const data = readKeystore();
	const org = data.orgs[clientId];
	if (!org) return undefined;
	return org.agents[org.default_agent_id];
}

/** Get a specific agent entry for an org */
export function getAgentEntry(clientId: string, agentId: string): KeystoreEntry | undefined {
	const data = readKeystore();
	const org = data.orgs[clientId];
	if (!org) return undefined;
	return org.agents[agentId];
}

/** Get all agent entries for an org */
export function getOrgAgents(clientId: string): Record<string, KeystoreEntry> {
	const data = readKeystore();
	return data.orgs[clientId]?.agents || {};
}

/** Save an agent entry. If it's the first agent, set it as default. */
export function saveOrgEntry(clientId: string, entry: KeystoreEntry): boolean {
	const data = readKeystore();
	if (!data.orgs[clientId]) {
		data.orgs[clientId] = { default_agent_id: entry.agent_id, agents: {} };
	}
	data.orgs[clientId].agents[entry.agent_id] = entry;
	// If no default or default doesn't exist anymore, set this as default
	if (!data.orgs[clientId].default_agent_id || !data.orgs[clientId].agents[data.orgs[clientId].default_agent_id]) {
		data.orgs[clientId].default_agent_id = entry.agent_id;
	}
	return writeKeystore(data);
}

/** Clear a specific agent from the org */
export function clearOrgEntry(clientId: string, agentId?: string): void {
	const data = readKeystore();
	const org = data.orgs[clientId];
	if (!org) return;

	if (agentId) {
		delete org.agents[agentId];
		// If we deleted the default, pick another or remove the org
		if (org.default_agent_id === agentId) {
			const remaining = Object.keys(org.agents);
			if (remaining.length > 0) {
				org.default_agent_id = remaining[0];
			} else {
				delete data.orgs[clientId];
			}
		}
	} else {
		delete data.orgs[clientId];
	}
	writeKeystore(data);
}

/** Update fields on a specific agent entry (defaults to the default agent) */
export function updateOrgEntry(clientId: string, updates: Partial<KeystoreEntry>, agentId?: string): boolean {
	const data = readKeystore();
	const org = data.orgs[clientId];
	if (!org) return false;
	const targetId = agentId || org.default_agent_id;
	const existing = org.agents[targetId];
	if (!existing) return false;
	org.agents[targetId] = { ...existing, ...updates };
	return writeKeystore(data);
}
