import { decodeJwt, errors, jwtVerify, type JWTPayload } from 'jose'
import { cleanProfile, profileTime } from '../profile'
import type { Config, Deps, IdpBinding, IdpConfig, LogCode, ProductConfig, Profile, TimeStatus } from '../types'
import { claim, mapClaims } from './claims'
import { JwksFetchError } from './fetch'
import { remoteJwks } from './jwks'

export interface VerifiedSubject {
    idp: IdpConfig
    subject: string
    // Unchecked until deriveUserId; absent when the token has no mapped uid.
    uid?: unknown
    profile: Profile
    // Set when the IdP maps updatedAt but the token gave no usable time; the exchange goes on without one
    updatedAtStatus?: TimeStatus
}

// The message is the log code alone, so nothing from the token is ever echoed
export class ExchangeError extends Error {
    override name = 'ExchangeError'
    readonly error: 'invalid_request' | 'temporarily_unavailable'
    readonly code: LogCode
    // Declared rather than defined, so the member is absent until the token's issuer selects a binding
    declare readonly idp?: string

    constructor(code: LogCode, idp?: string) {
        super(code)
        this.code = code
        this.error = code === 'jwks_unavailable' ? 'temporarily_unavailable' : 'invalid_request'
        if (idp !== undefined) this.idp = idp
    }
}

// Classify token/JWKS failures; let unexpected runtime errors reach the router.
export async function verifySubjectToken(token: string, product: ProductConfig, config: Config, deps: Deps): Promise<VerifiedSubject> {
    const bound = boundIdp(product, config, unverifiedIssuer(token))
    // No network call for an issuer the product does not trust
    if (bound === undefined) throw new ExchangeError('untrusted_issuer')
    const { binding, idp } = bound

    const payload = await verifySignature(token, idp, deps)
    for (const [name, value] of Object.entries(idp.requiredClaims)) {
        if (claim(payload, name) !== value) throw new ExchangeError('claim_mismatch', idp.id)
    }
    const mapped = mapClaims(payload, idp.claims)
    if (!clientBound(binding, mapped.clientIds, claim(payload, 'azp'))) throw new ExchangeError('client_mismatch', idp.id)
    const subject = claim(payload, 'sub')
    if (typeof subject !== 'string' || subject === '') throw new ExchangeError('missing_claim', idp.id)
    const verified: VerifiedSubject = { idp, subject, profile: cleanProfile(mapped.profile) }
    if (Object.hasOwn(mapped, 'uid')) verified.uid = mapped.uid
    if (idp.claims.updatedAt !== undefined) addTime(verified, mapped.updatedAt, idp, deps)
    return verified
}

// A missing time is not an error: while a Clerk rollout settles, edge-minted tokens can still carry the claim set
// from before it, and refusing them would lock users out
function addTime(verified: VerifiedSubject, value: unknown, idp: IdpConfig, deps: Deps): void {
    if (value === undefined || value === null) {
        verified.updatedAtStatus = 'missing'
        return
    }
    const time = profileTime(value, deps.now() / 1000, idp.clockToleranceSeconds)
    if (time === undefined) verified.updatedAtStatus = 'invalid'
    else verified.profile.updatedAt = time
}

function unverifiedIssuer(token: string): string {
    let payload: JWTPayload
    try {
        payload = decodeJwt(token)
    } catch {
        throw new ExchangeError('malformed_token')
    }
    const issuer = claim(payload, 'iss')
    if (typeof issuer !== 'string') throw new ExchangeError('malformed_token')
    return issuer
}

// Issuers are distinct across IdP records and a product binds each record once, so at most one binding matches
function boundIdp(product: ProductConfig, config: Config, issuer: string): { binding: IdpBinding; idp: IdpConfig } | undefined {
    for (const binding of product.idps) {
        const idp = config.idps[binding.idp]
        if (idp?.issuer === issuer) return { binding, idp }
    }
    return undefined
}

async function verifySignature(token: string, idp: IdpConfig, deps: Deps): Promise<JWTPayload> {
    const jwks = remoteJwks(idp, deps.fetch)
    // jose would raise a TypeError for it after fetching keys, which would read as the IdP being unavailable
    const now = deps.now()
    if (!Number.isFinite(now)) throw new Error('deps.now() must return a finite number')
    try {
        const { payload } = await jwtVerify(token, jwks, {
            issuer: idp.issuer,
            algorithms: idp.algorithms,
            clockTolerance: idp.clockToleranceSeconds,
            maxTokenAge: idp.maxTokenAgeSeconds,
            requiredClaims: ['exp', 'iat'],
            currentDate: new Date(now),
        })
        return payload
    } catch (error) {
        const code = failureCode(error, () => jwks.jwks() !== undefined)
        if (code === undefined) throw error
        throw new ExchangeError(code, idp.id)
    }
}

function failureCode(error: unknown, keyFetched: () => boolean): LogCode | undefined {
    if (error instanceof errors.JWTInvalid || error instanceof errors.JWSInvalid) return 'malformed_token'
    // Only an unsupported crit extension reaches it: the algorithm allowlist holds algorithms jose supports
    if (error instanceof errors.JOSENotSupported) return 'malformed_token'
    if (error instanceof errors.JWTClaimValidationFailed && error.reason === 'invalid') return 'malformed_token'
    if (error instanceof errors.JOSEAlgNotAllowed) return 'bad_algorithm'
    if (error instanceof errors.JWSSignatureVerificationFailed) return 'bad_signature'
    if (error instanceof errors.JWKSNoMatchingKey || error instanceof errors.JWKSMultipleMatchingKeys) return 'unknown_key'
    if (error instanceof errors.JWTExpired && error.claim === 'exp') return 'expired'
    if (error instanceof errors.JWTExpired && error.claim === 'iat') return 'too_old'
    if (error instanceof errors.JWTClaimValidationFailed && error.reason === 'missing') return 'missing_claim'
    if (error instanceof errors.JWTClaimValidationFailed && (error.claim === 'nbf' || error.claim === 'iat') && error.reason === 'check_failed') {
        return 'not_yet_valid'
    }
    if (error instanceof JwksFetchError || error instanceof errors.JWKSTimeout || error instanceof errors.JWKSInvalid) return 'jwks_unavailable'
    // jose raises these while importing or using a JWKS key, as for RSA under 2048 bits or a malformed member.
    // One raised before any key set was fetched, as for a missing runtime API, is not the IdP's doing.
    if ((error instanceof TypeError || isDomException(error)) && keyFetched()) return 'jwks_unavailable'
    return undefined
}

function isDomException(error: unknown): boolean {
    return typeof DOMException !== 'undefined' && error instanceof DOMException
}

function clientBound(binding: IdpBinding, clientIds: string[], azp: unknown): boolean {
    const { clientIds: allowedClients, authorizedParties } = binding
    if (allowedClients && !clientIds.some((id) => allowedClients.includes(id))) return false
    if (authorizedParties && !(typeof azp === 'string' && authorizedParties.includes(azp))) return false
    return true
}
