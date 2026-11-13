import type { ClaimMapping, RawProfile } from '../types'

// A token's claims set, whose values are not checked yet
export type Payload = Record<string, unknown>

export interface MappedClaims {
    clientIds: string[]
    // Present only when a uid claim is mapped and the token has it; its value is unchecked
    uid?: unknown
    profile: RawProfile
}

// Claim names come from configuration, where __proto__ or constructor is a valid name, so only a member of the
// payload itself counts, never one its prototype answers for
export function claim(payload: Payload, name: string): unknown {
    return Object.hasOwn(payload, name) ? payload[name] : undefined
}

export function mapClaims(payload: Payload, mapping: ClaimMapping): MappedClaims {
    const mapped: MappedClaims = {
        clientIds: clientIds(claim(payload, mapping.clientId)),
        profile: {
            email: claim(payload, mapping.email),
            emailVerified: verified(payload, mapping.emailVerified),
            phone: claim(payload, mapping.phone),
            phoneVerified: verified(payload, mapping.phoneVerified),
            name: claim(payload, mapping.name),
            picture: claim(payload, mapping.picture),
        },
    }
    if (mapping.uid !== undefined && Object.hasOwn(payload, mapping.uid)) mapped.uid = payload[mapping.uid]
    return mapped
}

// A string or an array, as aud may be
function clientIds(value: unknown): string[] {
    if (typeof value === 'string') return [value]
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
}

function verified(payload: Payload, flag: string | true): boolean {
    return flag === true || claim(payload, flag) === true
}
