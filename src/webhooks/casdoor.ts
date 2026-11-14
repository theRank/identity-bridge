import { constantTimeEqual } from '../crypto/compare'
import { cleanProfile } from '../profile'
import type { EventType, LifecycleEvent, Profile } from '../types'
import { BadPayloadError, isObject, own, parseObject, type JsonObject, type WebhookAdapter } from './adapter'

// Casdoor formats the outcome itself, not as JSON. ok also covers requests that changed nothing.
const OK = '{status:"ok"'
const BEARER = /^bearer +(.+)$/i

// Casdoor does not sign webhooks: the webhook is configured to send the secret as a bearer header
export const casdoor: WebhookAdapter = {
    async authenticate(request, _rawBody, secret) {
        const token = BEARER.exec(request.headers.get('authorization') ?? '')?.[1]
        if (token === undefined || secret === '') return false
        const encoder = new TextEncoder()
        return constantTimeEqual(encoder.encode(token), encoder.encode(secret))
    },

    parse(_request, rawBody, source) {
        if (source.type !== 'casdoor') throw new TypeError('not a casdoor source')
        const record = parseObject(rawBody, 'body')
        const name = own(record, 'name')
        const action = own(record, 'action')
        const organization = own(record, 'organization')
        const response = own(record, 'response')
        if (typeof name !== 'string' || typeof action !== 'string' || typeof organization !== 'string' || typeof response !== 'string') {
            throw new BadPayloadError('record lacks name, action, organization or response')
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
        // The record's own id is always 0, as Casdoor sends the webhook before storing the record
        const event: LifecycleEvent = { idpEventId: `${action}:${name}`, type, subject, profile: type === 'user-created' ? profile(user) : {} }
        if (source.uidField !== undefined) {
            // Without properties, "no override" and "override not sent" look the same
            const properties = own(user, 'properties')
            if (!Object.hasOwn(user, 'properties') || (properties !== null && !isObject(properties))) {
                throw new BadPayloadError('user properties are neither an object nor null')
            }
            const uid = properties === null ? undefined : own(properties, source.uidField)
            if (uid !== undefined) event.uid = uid
        }
        return [event]
    },
}

// new-user carries the stored user. Every other action carries the caller's raw body, and Casdoor lets users
// update and delete their own accounts, so a deletion is trusted only from an admin of the source's organization,
// who may write any of its users anyway. extendedUser is that actor, loaded by Casdoor from its store.
function eventType(action: string, actor: unknown, organization: string): EventType | undefined {
    if (action === 'new-user') return 'user-created'
    if (action === 'delete-user' && isObject(actor) && own(actor, 'isAdmin') === true && own(actor, 'owner') === organization) return 'user-deleted'
    return undefined
}

// No phone: Casdoor stores numbers without the calling code and has no verification flag for them
function profile(user: JsonObject): Profile {
    return cleanProfile({
        email: own(user, 'email'),
        emailVerified: own(user, 'emailVerified') === true,
        phoneVerified: false,
        name: own(user, 'displayName'),
        picture: own(user, 'avatar'),
    })
}
