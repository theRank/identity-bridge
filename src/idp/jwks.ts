import { createRemoteJWKSet, customFetch, type RemoteJWKSet } from 'jose'
import type { Deps, IdpConfig } from '../types'
import { JWKS_TIMEOUT_MS, jwksFetch } from './fetch'

// One key set per IdP for the isolate's lifetime, so fetched keys and the refetch cooldown carry across
// requests. jose keeps the fetch a set is created with, so each set uses the first deps.fetch it was given.
const sets = new Map<string, RemoteJWKSet>()
let cooldownDuration: number | undefined

export function remoteJwks(idp: IdpConfig, fetch: Deps['fetch']): RemoteJWKSet {
    let set = sets.get(idp.id)
    if (set === undefined) {
        set = createRemoteJWKSet(new URL(idp.jwksUri), {
            [customFetch]: jwksFetch(fetch),
            timeoutDuration: JWKS_TIMEOUT_MS,
            ...(cooldownDuration === undefined ? {} : { cooldownDuration }),
        })
        sets.set(idp.id, set)
    }
    return set
}

// For tests: forgets every set, and gives the sets created until the next reset the cooldown passed, or
// jose's default of 30 s
export function resetJwksCache(options: { cooldownDuration?: number } = {}): void {
    sets.clear()
    cooldownDuration = options.cooldownDuration
}
