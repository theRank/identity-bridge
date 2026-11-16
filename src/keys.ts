import { calculateJwkThumbprint, importJWK, type JWK } from 'jose'
import type { PublicJwk, SigningKeys } from './types'

const SECRET = 'SIGNING_KEYS'
const ACTIVE = `${SECRET}.active`
const ECDSA = { name: 'ECDSA', hash: 'SHA-256' }
const KEY_CHECK = new TextEncoder().encode('identity-bridge signing key check')

// The message names the member in fixed words. JSON.parse and jose error text can quote the input, which holds
// the private key, and the message reaches the runtime load log line, so neither is ever passed on.
export class KeyError extends Error {
    override name = 'KeyError'

    constructor(member: string, reason: string) {
        super(`${member}: ${reason}`)
    }
}

interface CheckedKey {
    jwk: PublicJwk
    publicKey: CryptoKey
    secret: { d?: string }
}

export async function importSigningKeys(json: string): Promise<SigningKeys> {
    let document: unknown
    try {
        document = JSON.parse(json)
    } catch {
        throw new KeyError(SECRET, 'invalid JSON')
    }
    if (!isObject(document)) throw new KeyError(SECRET, 'must be an object')
    // A misspelled retired would drop the keys that verify tokens signed before a rotation
    if (Object.keys(document).some((key) => key !== 'active' && key !== 'retired')) {
        throw new KeyError(SECRET, 'only active and retired are allowed')
    }
    if (document.active === undefined) throw new KeyError(ACTIVE, 'required')
    const retired = document.retired === undefined ? [] : document.retired
    if (!Array.isArray(retired)) throw new KeyError(`${SECRET}.retired`, 'must be an array')

    const active = await readKey(document.active, ACTIVE, true)
    const privateKey = await importPrivateKey(active, ACTIVE)
    const published = [active.jwk]
    for (const [index, item] of retired.entries()) {
        const member = `${SECRET}.retired[${index}]`
        const { jwk } = await readKey(item, member, false)
        if (published.some((earlier) => earlier.kid === jwk.kid)) throw new KeyError(member, 'repeats an earlier key')
        published.push(jwk)
    }

    const keys: SigningKeys = { kid: active.jwk.kid, privateKey, jwks: { keys: published } }
    for (const jwk of published) Object.freeze(jwk)
    Object.freeze(published)
    Object.freeze(keys.jwks)
    return Object.freeze(keys)
}

async function readKey(value: unknown, member: string, isPrivate: boolean): Promise<CheckedKey> {
    if (!isObject(value)) throw new KeyError(member, 'must be a JWK object')
    const { kty, crv, x, y, d, kid, alg, use } = value
    if (kty !== 'EC') throw new KeyError(member, 'must be an EC key')
    if (crv !== 'P-256') throw new KeyError(member, 'must use curve P-256')
    if (!isNonEmptyString(x) || !isNonEmptyString(y)) throw new KeyError(member, 'x and y required')
    let secret: { d?: string } = {}
    if (isPrivate) {
        if (!isNonEmptyString(d)) throw new KeyError(member, 'private key required')
        secret = { d }
    } else if (d !== undefined) {
        throw new KeyError(member, 'private key not allowed')
    }
    if (alg !== undefined && alg !== 'ES256') throw new KeyError(member, 'alg must be ES256')
    if (use !== undefined && use !== 'sig') throw new KeyError(member, 'use must be sig')

    // RFC 7638 over the JWK members: jose imports a private JWK as non-extractable, and refuses to
    // thumbprint such a key
    const thumbprint = await calculateJwkThumbprint({ kty, crv, x, y }).catch(() => undefined)
    if (thumbprint === undefined) throw new KeyError(member, 'not a valid P-256 key')
    if (kid !== undefined && kid !== thumbprint) throw new KeyError(member, 'kid must equal the key thumbprint')

    // Retired keys are imported too, so that a broken one fails the load rather than being published
    const publicKey = await importKey({ kty, crv, x, y })
    if (publicKey === undefined) throw new KeyError(member, 'not a valid P-256 key')
    return { jwk: { kty, crv, x, y, kid: thumbprint, alg: 'ES256', use: 'sig' }, publicKey, secret }
}

// Only the key members are imported, so ext and key_ops in the secret cannot make the key exportable or take
// away its sign usage. The round trip rejects a d that does not belong to x and y, which not every runtime does.
async function importPrivateKey({ jwk, publicKey, secret }: CheckedKey, member: string): Promise<CryptoKey> {
    const { kty, crv, x, y } = jwk
    const privateKey = await importKey({ kty, crv, x, y, ...secret })
    if (privateKey === undefined) throw new KeyError(member, 'not a valid P-256 key')
    const matches = await roundTrip(privateKey, publicKey)
    if (matches === undefined) throw new KeyError(member, 'not a valid P-256 key')
    if (!matches) throw new KeyError(member, 'private key does not match x and y')
    return privateKey
}

// undefined when the runtime cannot sign or verify with the keys at all
async function roundTrip(privateKey: CryptoKey, publicKey: CryptoKey): Promise<boolean | undefined> {
    try {
        const signature = await crypto.subtle.sign(ECDSA, privateKey, KEY_CHECK)
        return await crypto.subtle.verify(ECDSA, publicKey, signature, KEY_CHECK)
    } catch {
        return undefined
    }
}

// The error, whose text may quote the key, is dropped
async function importKey(jwk: JWK): Promise<CryptoKey | undefined> {
    const key = await importJWK(jwk, 'ES256').catch(() => undefined)
    return key instanceof CryptoKey ? key : undefined
}

function isObject(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isNonEmptyString(value: unknown): value is string {
    return typeof value === 'string' && value !== ''
}
