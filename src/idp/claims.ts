import { internationalNumber } from '../phone'
import type { ClaimMapping, RawProfile } from '../types'

export type Payload = Record<string, unknown>

export interface MappedClaims {
    clientIds: string[]
    // Present only when a uid claim is mapped and the token has it; its value is unchecked
    uid?: unknown
    profile: RawProfile
}

// Claim names come from configuration, where __proto__ and constructor are valid names, so only own members count
export function claim(payload: Payload, name: string): unknown {
    return Object.hasOwn(payload, name) ? payload[name] : undefined
}

export function mapClaims(payload: Payload, mapping: ClaimMapping): MappedClaims {
    const mapped: MappedClaims = {
        clientIds: clientIds(claim(payload, mapping.clientId)),
        profile: {
            email: claim(payload, mapping.email),
            emailVerified: verified(payload, mapping.emailVerified),
            phone: phone(payload, mapping),
            phoneVerified: verified(payload, mapping.phoneVerified),
            name: claim(payload, mapping.name),
            picture: claim(payload, mapping.picture),
        },
    }
    if (mapping.uid !== undefined && Object.hasOwn(payload, mapping.uid)) mapped.uid = payload[mapping.uid]
    return mapped
}

// With a region claim mapped, the phone claim is a national number, and one that does not make an international
// number with its region is no phone at all
function phone(payload: Payload, mapping: ClaimMapping): unknown {
    const value = claim(payload, mapping.phone)
    return mapping.phoneRegion === undefined ? value : internationalNumber(value, claim(payload, mapping.phoneRegion))
}

function clientIds(value: unknown): string[] {
    if (typeof value === 'string') return [value]
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
}

function verified(payload: Payload, flag: string | true): boolean {
    return flag === true || claim(payload, flag) === true
}
