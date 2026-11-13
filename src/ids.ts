// Both namespaces are fixed forever: changing either changes every id the bridge has ever issued
export const USER_ID_NAMESPACE = '95c1f512-a23b-48f7-8328-199bb33cc0b4'
export const EVENT_ID_NAMESPACE = '73c4ff75-fed7-4a0c-8541-3ff240e8f331'

// Any version and variant: an override names an id the product already uses
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
// Backends write these as empty defaults, which would merge every such user into one
const NIL_OR_MAX = /^(0{8}-0{4}-0{4}-0{4}-0{12}|f{8}-f{4}-f{4}-f{4}-f{12})$/i

// The message never quotes the value
export class BadUidError extends Error {
    override name = 'BadUidError'

    constructor() {
        super('uid override must be a canonical UUID')
    }
}

// RFC 9562 UUIDv5, with the name as UTF-8
export async function uuidV5(namespace: string, name: string): Promise<string> {
    if (!UUID.test(namespace)) throw new TypeError('namespace must be a canonical UUID')
    const nameBytes = new TextEncoder().encode(name)
    const input = new Uint8Array(16 + nameBytes.length)
    input.set(hexBytes(namespace.replace(/-/g, '')))
    input.set(nameBytes, 16)
    const bytes = new Uint8Array(await crypto.subtle.digest('SHA-1', input)).subarray(0, 16)
    bytes[6] = (bytes[6]! & 0x0f) | 0x50
    bytes[8] = (bytes[8]! & 0x3f) | 0x80
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

// A malformed override fails rather than falling back, which would give one person two ids. The callers check
// the subject too; checking again here means a missing one can never hash into an id shared by everyone.
export async function deriveUserId(idpIssuer: string, idpSubject: string, uid?: unknown): Promise<string> {
    if (!isNonEmptyString(idpIssuer) || !isNonEmptyString(idpSubject)) {
        throw new TypeError('idpIssuer and idpSubject must be non-empty strings')
    }
    if (uid === undefined || uid === null) return uuidV5(USER_ID_NAMESPACE, JSON.stringify([idpIssuer, idpSubject]))
    if (typeof uid === 'string' && UUID.test(uid) && !NIL_OR_MAX.test(uid)) return uid.toLowerCase()
    throw new BadUidError()
}

// Identical across redeliveries of one IdP event, so products can drop repeats by jti
export async function eventId(sourceId: string, idpEventId: string): Promise<string> {
    if (!isNonEmptyString(sourceId) || !isNonEmptyString(idpEventId)) throw new TypeError('sourceId and idpEventId must be non-empty strings')
    return uuidV5(EVENT_ID_NAMESPACE, JSON.stringify([sourceId, idpEventId]))
}

function isNonEmptyString(value: unknown): value is string {
    return typeof value === 'string' && value !== ''
}

function hexBytes(hex: string): Uint8Array {
    return Uint8Array.from({ length: hex.length / 2 }, (_, index) => parseInt(hex.slice(index * 2, index * 2 + 2), 16))
}
