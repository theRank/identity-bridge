import { constantTimeEqual } from '../crypto/compare'
import { cleanProfile } from '../profile'
import type { EventType, LifecycleEvent, Profile } from '../types'
import { BadPayloadError, isObject, own, parseObject, type JsonObject, type WebhookAdapter } from './adapter'

const TOLERANCE_SECONDS = 300
const SECRET_PREFIX = 'whsec_'
const TIMESTAMP = /^[0-9]{1,15}$/
// A Map, so an event type such as constructor never finds an Object.prototype member
const TYPES = new Map<string, EventType>([
    ['user.created', 'user-created'],
    ['user.updated', 'user-updated'],
    ['user.deleted', 'user-deleted'],
])

// Svix signs `${svix-id}.${svix-timestamp}.${body}` with HMAC-SHA256 and sends every valid signature, two while a
// secret is rotated, as space-separated `v1,<base64>` entries
export const clerk: WebhookAdapter = {
    async authenticate(request, rawBody, secret, nowMs) {
        const id = request.headers.get('svix-id')
        const timestamp = request.headers.get('svix-timestamp')
        const signatures = request.headers.get('svix-signature')
        if (!id || !timestamp || !signatures || !TIMESTAMP.test(timestamp)) return false
        if (Math.abs(Math.floor(nowMs / 1000) - Number(timestamp)) > TOLERANCE_SECONDS) return false
        const key = signingKey(secret)
        // An empty key is a deployment error that some HMAC implementations would accept, letting anyone sign
        if (key.byteLength === 0) return false
        const expected = encode(await sign(key, `${id}.${timestamp}.${rawBody}`))
        return signatures.split(' ').some((entry) => entry.startsWith('v1,') && constantTimeEqual(encode(entry.slice(3)), expected))
    },

    parse(request, rawBody, source) {
        const event = parseObject(rawBody, 'body')
        const type = own(event, 'type')
        const data = own(event, 'data')
        if (typeof type !== 'string' || !isObject(data)) throw new BadPayloadError('event lacks a type or data')
        const mapped = TYPES.get(type)
        if (mapped === undefined) return []
        // Present once authenticated; identical across Svix redeliveries
        const idpEventId = request.headers.get('svix-id')
        if (!idpEventId) throw new BadPayloadError('svix-id is missing')
        const subject = own(data, 'id')
        if (typeof subject !== 'string' || subject === '') throw new BadPayloadError('data.id is not a non-empty string')
        // Deleted users carry only their id and external_id
        const lifecycle: LifecycleEvent = { idpEventId, type: mapped, subject, profile: mapped === 'user-deleted' ? {} : profile(data) }
        // The configuration allows only external_id as a Clerk uidField. Absent or null means no override.
        if (source.uidField !== undefined && Object.hasOwn(data, 'external_id')) lifecycle.uid = own(data, 'external_id')
        if (mapped !== 'user-deleted') {
            // Clerk orders user events by updated_at; timestamp, when the event occurred, follows the write
            const times = [own(data, 'updated_at'), own(event, 'timestamp')]
                .filter((value) => value !== undefined)
                .map((value) => (typeof value === 'number' ? value / 1000 : value))
            if (times.length > 0) lifecycle.times = times
        }
        return [lifecycle]
    },
}

function profile(user: JsonObject): Profile {
    const email = verifiedPrimary(user, 'email_addresses', 'primary_email_address_id')
    const phone = verifiedPrimary(user, 'phone_numbers', 'primary_phone_number_id')
    const names = [own(user, 'first_name'), own(user, 'last_name')].filter((part) => typeof part === 'string')
    return cleanProfile({
        email: email && own(email, 'email_address'),
        emailVerified: email !== undefined,
        phone: phone && own(phone, 'phone_number'),
        phoneVerified: phone !== undefined,
        name: names.join(' '),
        picture: own(user, 'image_url'),
    })
}

function verifiedPrimary(user: JsonObject, list: string, primaryKey: string): JsonObject | undefined {
    const id = own(user, primaryKey)
    const entries = own(user, list)
    if (typeof id !== 'string' || !Array.isArray(entries)) return undefined
    const entry: unknown = entries.find((item) => isObject(item) && own(item, 'id') === id)
    if (!isObject(entry)) return undefined
    const verification = own(entry, 'verification')
    return isObject(verification) && own(verification, 'status') === 'verified' ? entry : undefined
}

// A secret that is not base64 is a deployment error: atob throws and the request fails as an internal error
function signingKey(secret: string): Uint8Array<ArrayBuffer> {
    const encoded = secret.startsWith(SECRET_PREFIX) ? secret.slice(SECRET_PREFIX.length) : secret
    return Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0))
}

async function sign(keyBytes: Uint8Array<ArrayBuffer>, content: string): Promise<string> {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, encode(content)))
    let binary = ''
    for (const byte of mac) binary += String.fromCharCode(byte)
    return btoa(binary)
}

function encode(text: string): Uint8Array {
    return new TextEncoder().encode(text)
}
