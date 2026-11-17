import { createRemoteJWKSet, customFetch, errors, jwtVerify, type FetchImplementation, type JWTPayload } from 'jose'

export interface VerifierOptions {
    /** The bridge's issuer URL, without a trailing slash. The keys are fetched from `${issuer}/.well-known/jwks.json`. */
    issuer: string
    /** Your product's id in the bridge configuration. */
    audience: string
    /** Leeway for `exp` and `nbf`, from 0 to 60. Default 60. */
    clockToleranceSeconds?: number | undefined
    /** Used to fetch the keys. Default: the global `fetch`. */
    fetch?: typeof fetch | undefined
}

export interface Verifier {
    /** Verifies a bridge access token. */
    verifyAccessToken(token: string): Promise<BridgeUser>
    /** Verifies the bearer token of the request's `Authorization` header. */
    verifyRequest(request: Request): Promise<BridgeUser>
    /** Verifies the body of an event delivery, which is the event token itself. */
    verifyEvent(body: string): Promise<BridgeEvent>
}

/** Email and phone number are present only when the identity provider verified them. */
export interface BridgeProfile {
    email?: string
    /** E.164. */
    phoneNumber?: string
    name?: string
    /** An avatar URL. */
    picture?: string
}

/** The user of a verified access token. */
export interface BridgeUser extends BridgeProfile {
    /** The user's id in the bridge, a lowercase UUID, the same in every access token and event for the user. */
    userId: string
    /** The bridge deployment's region label, when it has one. */
    region?: string
    /** When the token expires, in seconds since the epoch. */
    expiresAt: number
}

export type BridgeEventType = 'user-created' | 'user-updated' | 'user-deleted'

/** A verified user lifecycle event. */
export interface BridgeEvent {
    /** The event's id, the same on every delivery of the event: process each `jti` once. */
    jti: string
    type: BridgeEventType
    userId: string
    /** The user's current profile; empty for `user-deleted`. */
    profile: BridgeProfile
    /** When the bridge signed the event, in seconds since the epoch. */
    issuedAt: number
}

export type BridgeTokenErrorReason =
    | 'missing'
    | 'malformed'
    | 'wrong_algorithm'
    | 'unknown_key'
    | 'bad_signature'
    | 'expired'
    | 'wrong_type'
    | 'wrong_issuer'
    | 'wrong_audience'
    | 'invalid_claims'
    | 'jwks_unavailable'

/**
 * A verification failure with a fixed message and no `cause`, safe to log without exposing token claims.
 */
export class BridgeTokenError extends Error {
    override name = 'BridgeTokenError'
    readonly reason: BridgeTokenErrorReason

    // No cause, as jose's errors hold the decoded claims, email and phone included
    constructor(reason: BridgeTokenErrorReason) {
        super(`bridge token rejected: ${reason}`)
        this.reason = reason
    }
}

const JWKS_TIMEOUT_MS = 5000
const MAX_CLOCK_TOLERANCE_SECONDS = 60
const USER_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const BEARER = /^Bearer +(\S+)$/i
// A Map, so a member such as __proto__ never finds an Object.prototype member
const EVENT_TYPES = new Map<string, BridgeEventType>([
    ['urn:identity-bridge:event:user-created', 'user-created'],
    ['urn:identity-bridge:event:user-updated', 'user-updated'],
    ['urn:identity-bridge:event:user-deleted', 'user-deleted'],
])

// Never quotes the response
class JwksFetchError extends Error {
    override name = 'JwksFetchError'
}

class InvalidClaims extends Error {}

/**
 * A verifier of bridge access tokens and event tokens for one product. Create one and reuse it, so the bridge's
 * keys stay cached. Throws a `TypeError` or `RangeError` for invalid options. Every verification failure rejects
 * with a `BridgeTokenError`; a runtime missing a required Web API can reject with its own error.
 */
export function createVerifier(options: VerifierOptions): Verifier {
    const { issuer, audience, clockToleranceSeconds = MAX_CLOCK_TOLERANCE_SECONDS } = options
    // jose skips checks for undefined issuer/audience, which could allow another product's tokens.
    if (typeof issuer !== 'string' || issuer === '') throw new TypeError('issuer must be a non-empty string')
    if (typeof audience !== 'string' || audience === '') throw new TypeError('audience must be a non-empty string')
    if (typeof clockToleranceSeconds !== 'number') throw new TypeError('clockToleranceSeconds must be a number')
    if (!(clockToleranceSeconds >= 0 && clockToleranceSeconds <= MAX_CLOCK_TOLERANCE_SECONDS)) {
        throw new RangeError(`clockToleranceSeconds must be between 0 and ${MAX_CLOCK_TOLERANCE_SECONDS}`)
    }
    const jwks = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`), {
        [customFetch]: jwksFetch(options.fetch),
        timeoutDuration: JWKS_TIMEOUT_MS,
    })

    async function verify(token: unknown, typ: string, requiredClaims: string[]): Promise<JWTPayload> {
        if (typeof token !== 'string' || token === '') throw new BridgeTokenError('missing')
        try {
            const { payload } = await jwtVerify(token, jwks, { algorithms: ['ES256'], issuer, audience, typ, requiredClaims, clockTolerance: clockToleranceSeconds })
            return payload
        } catch (error) {
            const reason = failureReason(error, () => jwks.jwks() !== undefined)
            if (reason === undefined) throw error
            throw new BridgeTokenError(reason)
        }
    }

    // typ is normalized by jose, so application/at+jwt and application/secevent+jwt are accepted too. Both kinds
    // are signed with the same keys, and an event has no exp: the typ check keeps one from passing as the other.
    async function verifyAccessToken(token: string): Promise<BridgeUser> {
        return checked(bridgeUser, await verify(token, 'at+jwt', ['exp', 'iat', 'sub']))
    }

    return {
        verifyAccessToken,

        async verifyRequest(request) {
            const match = BEARER.exec(request.headers.get('authorization') ?? '')
            if (match === null) throw new BridgeTokenError('missing')
            return verifyAccessToken(match[1]!)
        },

        async verifyEvent(body) {
            return checked(bridgeEvent, await verify(body, 'secevent+jwt', ['iat', 'jti', 'sub']))
        },
    }
}

function checked<T>(read: (payload: JWTPayload) => T, payload: JWTPayload): T {
    try {
        return read(payload)
    } catch (error) {
        if (error instanceof InvalidClaims) throw new BridgeTokenError('invalid_claims')
        throw error
    }
}

// The idp claim is left out on purpose: products must not branch on the identity provider
function bridgeUser(payload: JWTPayload): BridgeUser {
    const user: BridgeUser = { userId: userId(payload.sub), ...profile(payload), expiresAt: payload.exp! }
    const region = optionalString(payload.region)
    if (region !== undefined) user.region = region
    return user
}

function bridgeEvent(payload: JWTPayload): BridgeEvent {
    const { jti, events } = payload
    if (typeof jti !== 'string' || jti === '' || !isRecord(events)) throw new InvalidClaims()
    const names = Object.keys(events)
    const type = names.length === 1 ? EVENT_TYPES.get(names[0]!) : undefined
    const event = names.length === 1 ? events[names[0]!] : undefined
    if (type === undefined || !isRecord(event)) throw new InvalidClaims()
    return { jti, type, userId: userId(payload.sub), profile: type === 'user-deleted' ? {} : profile(event), issuedAt: payload.iat! }
}

function profile(claims: Record<string, unknown>): BridgeProfile {
    const result: BridgeProfile = {}
    const email = optionalString(claims.email)
    const phoneNumber = optionalString(claims.phone_number)
    const name = optionalString(claims.name)
    const picture = optionalString(claims.picture)
    if (email !== undefined) result.email = email
    if (phoneNumber !== undefined) result.phoneNumber = phoneNumber
    if (name !== undefined) result.name = name
    if (picture !== undefined) result.picture = picture
    return result
}

function userId(sub: unknown): string {
    if (typeof sub !== 'string' || !USER_ID.test(sub)) throw new InvalidClaims()
    return sub
}

function optionalString(value: unknown): string | undefined {
    if (value !== undefined && typeof value !== 'string') throw new InvalidClaims()
    return value
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value)
}

// Rows in order: several reasons share an error class and differ only in claim or reason
function failureReason(error: unknown, keysFetched: () => boolean): BridgeTokenErrorReason | undefined {
    if (error instanceof errors.JWSInvalid || error instanceof errors.JWTInvalid || error instanceof errors.JOSENotSupported) return 'malformed'
    if (error instanceof errors.JWTClaimValidationFailed && error.reason === 'invalid') return 'malformed'
    if (error instanceof errors.JOSEAlgNotAllowed) return 'wrong_algorithm'
    if (error instanceof errors.JWKSNoMatchingKey || error instanceof errors.JWKSMultipleMatchingKeys) return 'unknown_key'
    if (error instanceof errors.JWSSignatureVerificationFailed) return 'bad_signature'
    if (error instanceof errors.JWTExpired) return 'expired'
    if (error instanceof errors.JWTClaimValidationFailed) {
        if (error.claim === 'typ') return 'wrong_type'
        if (error.claim === 'iss') return 'wrong_issuer'
        if (error.claim === 'aud') return 'wrong_audience'
        return 'invalid_claims'
    }
    if (error instanceof JwksFetchError || error instanceof errors.JWKSTimeout || error instanceof errors.JWKSInvalid) return 'jwks_unavailable'
    // jose raises these while importing a published key it cannot use. One raised before any key set was fetched,
    // as for a missing runtime API, is not the bridge's doing.
    if ((error instanceof TypeError || isDomException(error)) && keysFetched()) return 'jwks_unavailable'
    return undefined
}

// Not every runtime defines DOMException
function isDomException(error: unknown): boolean {
    return typeof DOMException !== 'undefined' && error instanceof DOMException
}

// Distinguish fetch failures from other jose errors. Bound the body read even if fetch ignores abort signals.
function jwksFetch(given: typeof fetch | undefined): FetchImplementation {
    return (url, init) => withTimeout(load(given ?? fetch, url, init), JWKS_TIMEOUT_MS)
}

async function load(fetchJwks: typeof fetch, url: string, init: RequestInit): Promise<Response> {
    let response: Response
    try {
        response = await fetchJwks(url, init)
    } catch {
        throw new JwksFetchError('JWKS request failed')
    }
    if (response.status !== 200) {
        // Releases the connection rather than leaving the body unread
        await response.body?.cancel().catch(() => {})
        throw new JwksFetchError('JWKS response status is not 200')
    }
    let text: string
    try {
        text = new TextDecoder().decode(await response.arrayBuffer())
    } catch {
        throw new JwksFetchError('JWKS response body could not be read')
    }
    let body: unknown
    try {
        body = JSON.parse(text)
    } catch {
        throw new JwksFetchError('JWKS response is not JSON')
    }
    if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new JwksFetchError('JWKS response is not a JSON object')
    return new Response(text, { status: 200, headers: { 'content-type': 'application/json' } })
}

function withTimeout<T>(work: Promise<T>, ms: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => reject(new JwksFetchError('JWKS request timed out')), ms)
        work.then(resolve, reject).finally(() => clearTimeout(timer))
    })
}
