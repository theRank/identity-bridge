import { createRemoteJWKSet, customFetch, errors, jwtVerify, type FetchImplementation, type JWTPayload } from 'jose'

export interface VerifierOptions {
    // The bridge issuer, without a trailing slash
    issuer: string
    // The product's own id
    audience: string
    // 0 to 60, default 60
    clockToleranceSeconds?: number
    // For the JWKS; the global fetch by default
    fetch?: typeof fetch
}

export interface Verifier {
    verifyAccessToken(token: string): Promise<BridgeUser>
    // Reads the Authorization: Bearer header
    verifyRequest(request: Request): Promise<BridgeUser>
}

// Times are seconds since the epoch, as in the token
export interface BridgeUser {
    userId: string
    email?: string
    phoneNumber?: string
    name?: string
    picture?: string
    region?: string
    expiresAt: number
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

// Carries no cause and its message only the reason: jose's errors hold the decoded claims, email and phone included
export class BridgeTokenError extends Error {
    override name = 'BridgeTokenError'
    readonly reason: BridgeTokenErrorReason

    constructor(reason: BridgeTokenErrorReason) {
        super(`bridge token rejected: ${reason}`)
        this.reason = reason
    }
}

const JWKS_TIMEOUT_MS = 5000
const MAX_CLOCK_TOLERANCE_SECONDS = 60
const USER_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const BEARER = /^Bearer +(\S+)$/i

// Never quotes the response
class JwksFetchError extends Error {
    override name = 'JwksFetchError'
}

class InvalidClaims extends Error {}

export function createVerifier(options: VerifierOptions): Verifier {
    const { issuer, audience, clockToleranceSeconds = MAX_CLOCK_TOLERANCE_SECONDS } = options
    if (!(clockToleranceSeconds >= 0 && clockToleranceSeconds <= MAX_CLOCK_TOLERANCE_SECONDS)) {
        throw new RangeError(`clockToleranceSeconds must be between 0 and ${MAX_CLOCK_TOLERANCE_SECONDS}`)
    }
    // One key set per verifier, so its keys and refetch cooldown carry across calls
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

    async function verifyAccessToken(token: string): Promise<BridgeUser> {
        // typ is normalized by jose, so application/at+jwt is accepted too
        const payload = await verify(token, 'at+jwt', ['exp', 'iat', 'sub'])
        try {
            return bridgeUser(payload)
        } catch (error) {
            if (error instanceof InvalidClaims) throw new BridgeTokenError('invalid_claims')
            throw error
        }
    }

    return {
        verifyAccessToken,

        verifyRequest(request) {
            const match = BEARER.exec(request.headers.get('authorization') ?? '')
            if (match === null) return Promise.reject(new BridgeTokenError('missing'))
            return verifyAccessToken(match[1]!)
        },
    }
}

// The idp claim is left out on purpose: products must not branch on the identity provider
function bridgeUser(payload: JWTPayload): BridgeUser {
    const user: BridgeUser = { userId: userId(payload.sub), expiresAt: payload.exp! }
    const email = optionalString(payload.email)
    const phoneNumber = optionalString(payload.phone_number)
    const name = optionalString(payload.name)
    const picture = optionalString(payload.picture)
    const region = optionalString(payload.region)
    if (email !== undefined) user.email = email
    if (phoneNumber !== undefined) user.phoneNumber = phoneNumber
    if (name !== undefined) user.name = name
    if (picture !== undefined) user.picture = picture
    if (region !== undefined) user.region = region
    return user
}

function userId(sub: unknown): string {
    if (typeof sub !== 'string' || !USER_ID.test(sub)) throw new InvalidClaims()
    return sub
}

function optionalString(value: unknown): string | undefined {
    if (value !== undefined && typeof value !== 'string') throw new InvalidClaims()
    return value
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

// jose throws a generic JOSEError for a non-200 or non-JSON answer, which could not be told apart from other
// failures, so every failure here is a JwksFetchError. The timer races jose's abort signal because a runtime
// without AbortController cannot abort the fetch; it covers reading the body too.
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
