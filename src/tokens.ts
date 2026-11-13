import { SignJWT, type JWTPayload } from 'jose'
import type { Config, EventType, Profile, SigningKeys } from './types'

export interface TokenIdentity {
    userId: string
    idpId: string
    profile: Profile
}

export interface TokenEvent {
    jti: string
    txn: string
    userId: string
    type: EventType
    profile: Profile
}

// nowSec is passed to every time setter, so jose never reads the clock
export function mintAccessToken(
    keys: SigningKeys,
    config: Config,
    productId: string,
    identity: TokenIdentity,
    nowSec: number,
    jti: string,
): Promise<string> {
    const claims: JWTPayload = { iss: config.issuer, sub: identity.userId, aud: productId, client_id: productId, jti, idp: identity.idpId }
    if (config.region !== undefined) claims.region = config.region
    return new SignJWT({ ...claims, ...profileClaims(identity.profile) })
        .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: keys.kid })
        .setIssuedAt(nowSec)
        .setExpirationTime(nowSec + config.tokenTtlSeconds)
        .sign(keys.privateKey)
}

// A SET carries no exp: products drop repeats by jti instead
export function mintEventToken(keys: SigningKeys, config: Config, productId: string, event: TokenEvent, nowSec: number): Promise<string> {
    const payload = event.type === 'user-deleted' ? {} : profileClaims(event.profile)
    return new SignJWT({
        iss: config.issuer,
        aud: productId,
        jti: event.jti,
        txn: event.txn,
        sub: event.userId,
        events: { [`urn:identity-bridge:event:${event.type}`]: payload },
    })
        .setProtectedHeader({ alg: 'ES256', typ: 'secevent+jwt', kid: keys.kid })
        .setIssuedAt(nowSec)
        .sign(keys.privateKey)
}

// Members are copied one by one, so nothing else a Profile object holds can become a claim
function profileClaims(profile: Profile): Record<string, string> {
    const claims: Record<string, string> = {}
    if (profile.email !== undefined) claims.email = profile.email
    if (profile.phoneNumber !== undefined) claims.phone_number = profile.phoneNumber
    if (profile.name !== undefined) claims.name = profile.name
    if (profile.picture !== undefined) claims.picture = profile.picture
    return claims
}
