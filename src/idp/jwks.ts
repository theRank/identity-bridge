import { createRemoteJWKSet, customFetch, type RemoteJWKSet } from 'jose'
import type { Deps, IdpConfig } from '../types'
import { JWKS_TIMEOUT_MS, jwksFetch } from './fetch'

// Cache per parsed IdP record; the key set retains the first fetch implementation it receives.
let sets = new WeakMap<IdpConfig, RemoteJWKSet>()
let cooldownDuration: number | undefined

export function remoteJwks(idp: IdpConfig, fetch: Deps['fetch']): RemoteJWKSet {
    let set = sets.get(idp)
    if (set === undefined) {
        set = createRemoteJWKSet(new URL(idp.jwksUri), {
            [customFetch]: jwksFetch(fetch),
            timeoutDuration: JWKS_TIMEOUT_MS,
            ...(cooldownDuration === undefined ? {} : { cooldownDuration }),
        })
        sets.set(idp, set)
    }
    return set
}

// Test hook: clear cached sets and optionally override the cooldown for new ones.
export function resetJwksCache(options: { cooldownDuration?: number } = {}): void {
    sets = new WeakMap()
    cooldownDuration = options.cooldownDuration
}
