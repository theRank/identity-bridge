import { constantTimeEqual } from '../crypto/compare'
import { internationalNumber } from '../phone'
import { cleanProfile } from '../profile'
import type { EventType, IdpConfig, LifecycleEvent, Profile } from '../types'
import { BadPayloadError, isObject, own, parseObject, type JsonObject, type WebhookAdapter } from './adapter'

// Casdoor formats the outcome itself, not as JSON. ok also covers requests that changed nothing.
const OK = '{status:"ok"'
const BEARER = /^bearer +(.+)$/i
// RFC 3339 as Casdoor writes it: whole seconds and the server's offset; fractions accepted
const RFC3339 = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/

// Casdoor does not sign webhooks: the webhook is configured to send the secret as a bearer header
export const casdoor: WebhookAdapter = {
    async authenticate(request, _rawBody, secret) {
        const token = BEARER.exec(request.headers.get('authorization') ?? '')?.[1]
        if (token === undefined || secret === '') return false
        const encoder = new TextEncoder()
        return constantTimeEqual(encoder.encode(token), encoder.encode(secret))
    },

    parse(_request, rawBody, source, idp) {
        if (source.type !== 'casdoor') throw new TypeError('not a casdoor source')
        const record = parseObject(rawBody, 'body')
        const id = own(record, 'id')
        const action = own(record, 'action')
        const organization = own(record, 'organization')
        const response = own(record, 'response')
        // Before Casdoor 4.28, every webhook had id 0, collapsing distinct events into one.
        if (typeof id !== 'number' || !Number.isSafeInteger(id) || id <= 0) throw new BadPayloadError('record id is not a positive integer')
        if (typeof action !== 'string' || typeof organization !== 'string' || typeof response !== 'string') {
            throw new BadPayloadError('record lacks action, organization or response')
        }
        // statusCode does not reflect the outcome: 200 on API records, 0 on new-user copies
        if (organization !== source.organization || !response.startsWith(OK)) return []
        const type = eventType(action, own(record, 'extendedUser'), source.organization)
        if (type === undefined) return []

        const text = own(record, 'object')
        if (typeof text !== 'string') throw new BadPayloadError('record object is not a string')
        const user = parseObject(text, 'record object')
        if (type === 'user-deleted' && own(user, 'owner') !== source.organization) return []
        const subject = own(user, 'id')
        if (typeof subject !== 'string' || subject === '') throw new BadPayloadError('user id is not a non-empty string')
        const event: LifecycleEvent = { idpEventId: String(id), type, subject, profile: type === 'user-created' ? profile(user, idp) : {} }
        if (source.uidField !== undefined) {
            // Without properties, "no override" and "override not sent" look the same
            const properties = own(user, 'properties')
            if (!Object.hasOwn(user, 'properties') || (properties !== null && !isObject(properties))) {
                throw new BadPayloadError('user properties are neither an object nor null')
            }
            const uid = properties === null ? undefined : own(properties, source.uidField)
            if (uid !== undefined) event.uid = uid
        }
        // The server sets the record's time after the sign-up. The user's own times can come from API callers.
        if (type === 'user-created' && Object.hasOwn(record, 'createdTime')) event.times = [recordTime(own(record, 'createdTime'))]
        return [event]
    },
}

// Date.parse is specified for exactly three fraction digits, so the fraction is cut or padded to three first
function recordTime(value: unknown): unknown {
    const match = typeof value === 'string' ? RFC3339.exec(value) : null
    if (match === null) return value
    const [, dateTime, fraction = '', offset] = match
    const ms = Date.parse(`${dateTime}.${fraction.slice(0, 3).padEnd(3, '0')}${offset}`)
    return Number.isFinite(ms) ? ms / 1000 : value
}

// new-user carries stored data; delete-user carries caller input. Trust deletions only from an organization
// admin, identified by Casdoor's stored extendedUser, who already has write access to those users.
function eventType(action: string, actor: unknown, organization: string): EventType | undefined {
    if (action === 'new-user') return 'user-created'
    if (action === 'delete-user' && isObject(actor) && own(actor, 'isAdmin') === true && own(actor, 'owner') === organization) return 'user-deleted'
    return undefined
}

// Casdoor has no phone verification flag; match the token path's explicit trust in its verification policy.
function profile(user: JsonObject, idp: IdpConfig): Profile {
    return cleanProfile({
        email: own(user, 'email'),
        emailVerified: own(user, 'emailVerified') === true,
        phone: internationalNumber(own(user, 'phone'), own(user, 'countryCode')),
        phoneVerified: idp.claims.phoneVerified === true,
        name: own(user, 'displayName'),
        picture: own(user, 'avatar'),
    })
}
