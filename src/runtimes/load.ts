import { ConfigError, parseConfig } from '../config'
import { importSigningKeys, KeyError } from '../keys'
import type { Runtime, RuntimeFailure } from '../types'

export interface RuntimeSource {
    config?: string | undefined
    signingKeys?: string | undefined
    webhookSecret(sourceId: string): string | undefined
}

// A message built only from fixed words and source ids
class LoadFailure extends Error {}

// Source ids are lowercase letters, digits and -, so no two ids share a name
export function webhookSecretName(sourceId: string): `WEBHOOK_SECRET_${string}` {
    return `WEBHOOK_SECRET_${sourceId.toUpperCase().replaceAll('-', '_')}`
}

// Convert failures to safe log messages; parser and crypto errors may contain secrets.
export async function loadRuntime(source: RuntimeSource): Promise<Runtime | RuntimeFailure> {
    try {
        return await load(source)
    } catch (error) {
        return { reason: reason(error) }
    }
}

async function load(source: RuntimeSource): Promise<Runtime> {
    if (!source.config) throw new LoadFailure('missing BRIDGE_CONFIG')
    const config = parseConfig(source.config)
    if (!source.signingKeys) throw new LoadFailure('missing SIGNING_KEYS')
    const keys = await importSigningKeys(source.signingKeys)
    // Reject surrounding whitespace before headers can trim it and break Casdoor authentication.
    // Apply the same rule to Clerk; format and signature checks happen during authentication.
    const secrets = new Map<string, string>()
    for (const id of Object.keys(config.webhookSources)) {
        const secret = source.webhookSecret(id)
        if (!secret) throw new LoadFailure(`missing webhook secret for source ${id}`)
        if (secret !== secret.trim()) throw new LoadFailure(`webhook secret for source ${id} has surrounding whitespace`)
        secrets.set(id, secret)
    }
    return Object.freeze({
        config,
        keys,
        webhookSecret(sourceId: string): string {
            const secret = secrets.get(sourceId)
            if (secret === undefined) throw new Error('no webhook secret for an unconfigured source')
            return secret
        },
    })
}

function reason(error: unknown): string {
    if (error instanceof LoadFailure) return error.message
    if (error instanceof ConfigError) return `config: ${error.message}`
    if (error instanceof KeyError) return error.message
    return 'unexpected error'
}
