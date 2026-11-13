import { decodeJwt, errors, jwtVerify, type JWTPayload } from 'jose'
import { cleanProfile } from '../profile'
import type { Config, Deps, IdpBinding, IdpConfig, LogCode, ProductConfig, Profile } from '../types'
import { claim, mapClaims } from './claims'
import { JwksFetchError } from './fetch'
import { remoteJwks } from './jwks'

export interface VerifiedSubject {
    idp: IdpConfig
    subject: string
    // The raw value of the mapped uid claim, for deriveUserId to check; absent when the token has none
    uid?: unknown
    profile: Profile
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

// Each failure throws ExchangeError; an error it cannot classify is rethrown as it is
export async function verifySubjectToken(token: string, product: ProductConfig, config: Config, deps: Deps): Promise<VerifiedSubject> {
    const issuer = unverifiedIssuer(token)
    // Issuers are distinct across IdP records and a product binds each record once, so at most one matches
    const binding = product.idps.find((candidate) => config.idps[candidate.idp]?.issuer === issuer)
    const idp = binding && config.idps[binding.idp]
    // No network call for an issuer the product does not trust
    if (binding === undefined || idp === undefined) throw new ExchangeError('untrusted_issuer')

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
    return verified
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

// Rows in order: several outcomes share a class and differ only in claim or reason, and the row for a time
// claim that is not a number comes before the nbf and iat rows
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

// Not every runtime defines DOMException
function isDomException(error: unknown): boolean {
    return typeof DOMException !== 'undefined' && error instanceof DOMException
}

function clientBound(binding: IdpBinding, clientIds: string[], azp: unknown): boolean {
    const { clientIds: allowedClients, authorizedParties } = binding
    if (allowedClients && !clientIds.some((id) => allowedClients.includes(id))) return false
    if (authorizedParties && !(typeof azp === 'string' && authorizedParties.includes(azp))) return false
    return true
}
