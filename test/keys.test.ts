import { calculateJwkThumbprint, createLocalJWKSet, jwtVerify, SignJWT } from 'jose'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { importSigningKeys, KeyError } from '../src/keys'
import { bridgeSigningKeys } from './helpers/keys'

// Cases edit the secret into any shape, invalid ones included
type Doc = Record<string, any>

const MEMBERS = ['alg', 'crv', 'kid', 'kty', 'use', 'x', 'y']

function publicPart(jwk: JsonWebKey): JsonWebKey {
    return { kty: jwk.kty!, crv: jwk.crv!, x: jwk.x!, y: jwk.y! }
}

async function rejection(json: string): Promise<KeyError> {
    const error = await importSigningKeys(json).then(
        () => undefined,
        (caught: unknown) => caught,
    )
    expect(error).toBeInstanceOf(KeyError)
    return error as KeyError
}

// Shorter runs could occur by chance in fixed English text; a run of six would mean the value was quoted
function runsOf(value: string, length = 6): string[] {
    return Array.from({ length: Math.max(value.length - length + 1, 0) }, (_, index) => value.slice(index, index + length))
}

function privateValues(doc: unknown): string[] {
    if (typeof doc !== 'object' || doc === null) return []
    const own = 'd' in doc && typeof doc.d === 'string' ? [doc.d] : []
    return [...own, ...Object.values(doc).flatMap(privateValues)]
}

async function p384PrivateJwk(): Promise<JsonWebKey> {
    const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify'])) as CryptoKeyPair
    const { kty, crv, x, y, d } = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey
    return { kty: kty!, crv: crv!, x: x!, y: y!, d: d! }
}

describe('importSigningKeys', () => {
    it('imports the active key and publishes it first, then the retired keys', async () => {
        const secret = await bridgeSigningKeys(2)
        const keys = await importSigningKeys(secret.json)
        const thumbprints = await Promise.all([secret.active, ...secret.retired].map((jwk) => calculateJwkThumbprint(publicPart(jwk))))
        expect(keys.kid).toBe(thumbprints[0])
        expect(keys.jwks).toStrictEqual({
            keys: [secret.active, ...secret.retired].map((jwk, index) => ({
                kty: 'EC',
                crv: 'P-256',
                x: jwk.x,
                y: jwk.y,
                kid: thumbprints[index],
                alg: 'ES256',
                use: 'sig',
            })),
        })
    })

    // Computed here without jose: SHA-256 of the required members in lexical order, no whitespace
    it('uses the RFC 7638 SHA-256 thumbprint as each kid', async () => {
        const secret = await bridgeSigningKeys(2)
        const keys = await importSigningKeys(secret.json)
        for (const [index, jwk] of [secret.active, ...secret.retired].entries()) {
            const input = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
            const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input)))
            const kid = btoa(String.fromCharCode(...digest)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
            expect(kid).toMatch(/^[A-Za-z0-9_-]{43}$/)
            expect(keys.jwks.keys[index]!.kid).toBe(kid)
        }
        expect(keys.kid).toBe(keys.jwks.keys[0]!.kid)
    })

    it('publishes exactly the public members', async () => {
        const secret = await bridgeSigningKeys(1)
        const kid = await calculateJwkThumbprint(publicPart(secret.active))
        const jwk = { ...secret.active, kid, alg: 'ES256', use: 'sig', ext: true, key_ops: ['sign'] }
        const keys = await importSigningKeys(JSON.stringify({ active: jwk, retired: secret.retired }))
        for (const key of keys.jwks.keys) {
            expect(Object.keys(key).sort()).toEqual(MEMBERS)
            expect(key).not.toHaveProperty('d')
        }
        expect(JSON.stringify(keys.jwks)).not.toContain(secret.active.d)
    })

    it('gives a private ES256 signing key that cannot be exported', async () => {
        const secret = await bridgeSigningKeys()
        const { privateKey } = await importSigningKeys(JSON.stringify({ active: { ...secret.active, ext: true } }))
        expect(privateKey).toBeInstanceOf(CryptoKey)
        expect(privateKey.type).toBe('private')
        expect(privateKey.extractable).toBe(false)
        expect(privateKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' })
        expect(privateKey.usages).toEqual(['sign'])
    })

    it('ignores ext and key_ops in the secret', async () => {
        const secret = await bridgeSigningKeys()
        const keys = await importSigningKeys(JSON.stringify({ active: { ...secret.active, ext: true, key_ops: ['verify'] } }))
        expect(keys.privateKey.extractable).toBe(false)
        expect(keys.privateKey.usages).toEqual(['sign'])
        await new SignJWT({ sub: 'user' }).setProtectedHeader({ alg: 'ES256', kid: keys.kid }).sign(keys.privateKey)
    })

    it('signs tokens that verify against its own JWKS', async () => {
        const keys = await importSigningKeys((await bridgeSigningKeys(1)).json)
        const token = await new SignJWT({ sub: 'user' }).setProtectedHeader({ alg: 'ES256', kid: keys.kid }).sign(keys.privateKey)
        const { protectedHeader } = await jwtVerify(token, createLocalJWKSet(keys.jwks), { algorithms: ['ES256'] })
        expect(protectedHeader.kid).toBe(keys.kid)
    })

    it('keeps tokens signed before a rotation verifiable through the retired keys', async () => {
        const [before, next] = await Promise.all([bridgeSigningKeys(), bridgeSigningKeys()])
        const old = await importSigningKeys(before.json)
        const token = await new SignJWT({ sub: 'user' }).setProtectedHeader({ alg: 'ES256', kid: old.kid }).sign(old.privateKey)
        const rotated = await importSigningKeys(JSON.stringify({ active: next.active, retired: [publicPart(before.active)] }))
        expect(rotated.kid).not.toBe(old.kid)
        expect(rotated.jwks.keys[1]!.kid).toBe(old.kid)
        await jwtVerify(token, createLocalJWKSet(rotated.jwks), { algorithms: ['ES256'] })
    })

    it('accepts a secret without retired keys', async () => {
        const secret = await bridgeSigningKeys()
        const keys = await importSigningKeys(JSON.stringify({ active: secret.active }))
        expect(keys.jwks.keys).toHaveLength(1)
        expect(keys.jwks.keys[0]!.kid).toBe(keys.kid)
        expect((await importSigningKeys(JSON.stringify({ active: secret.active, retired: [] }))).jwks).toEqual(keys.jwks)
    })

    it('accepts keys whose kid, alg and use agree with the published ones', async () => {
        const secret = await bridgeSigningKeys(1)
        const retired = secret.retired[0]!
        const keys = await importSigningKeys(
            JSON.stringify({
                active: { ...secret.active, kid: await calculateJwkThumbprint(publicPart(secret.active)), alg: 'ES256', use: 'sig' },
                retired: [{ ...retired, kid: await calculateJwkThumbprint(publicPart(retired)), alg: 'ES256', use: 'sig' }],
            }),
        )
        expect(keys.jwks.keys).toHaveLength(2)
    })

    it('freezes the published JWKS', async () => {
        const keys = await importSigningKeys((await bridgeSigningKeys(1)).json)
        expect(Object.isFrozen(keys)).toBe(true)
        expect(Object.isFrozen(keys.jwks)).toBe(true)
        expect(Object.isFrozen(keys.jwks.keys)).toBe(true)
        for (const key of keys.jwks.keys) expect(Object.isFrozen(key)).toBe(true)
    })
})

describe('importSigningKeys rejections', () => {
    // Members set to undefined are left out when the secret is serialized
    const active = (doc: Doc, members: Doc) => ({ ...doc, active: { ...doc.active, ...members } })
    const retired = (doc: Doc, ...keys: unknown[]) => ({ ...doc, retired: keys })
    const another = async () => (await bridgeSigningKeys()).active

    const CASES: [name: string, edit: (doc: Doc) => Promise<unknown> | unknown, message: string][] = [
        ['a document that is null', () => null, 'SIGNING_KEYS: must be an object'],
        ['a document that is an array', (doc) => [doc], 'SIGNING_KEYS: must be an object'],
        ['a document that is a string', (doc) => JSON.stringify(doc), 'SIGNING_KEYS: must be an object'],
        ['an unknown member', (doc) => ({ ...doc, retierd: [] }), 'SIGNING_KEYS: only active and retired are allowed'],
        ['a missing active key', (doc) => ({ retired: doc.retired }), 'SIGNING_KEYS.active: required'],
        ['an active key that is null', (doc) => ({ ...doc, active: null }), 'SIGNING_KEYS.active: must be a JWK object'],
        ['an active key that is an array', (doc) => ({ ...doc, active: [doc.active] }), 'SIGNING_KEYS.active: must be a JWK object'],
        ['an active key that is a string', (doc) => ({ ...doc, active: JSON.stringify(doc.active) }), 'SIGNING_KEYS.active: must be a JWK object'],
        ['an active RSA key', (doc) => active(doc, { kty: 'RSA' }), 'SIGNING_KEYS.active: must be an EC key'],
        ['an active key without kty', (doc) => active(doc, { kty: undefined }), 'SIGNING_KEYS.active: must be an EC key'],
        ['an active P-384 key', async (doc) => ({ ...doc, active: await p384PrivateJwk() }), 'SIGNING_KEYS.active: must use curve P-256'],
        ['an active key on curve secp256k1', (doc) => active(doc, { crv: 'secp256k1' }), 'SIGNING_KEYS.active: must use curve P-256'],
        ['an active key without x', (doc) => active(doc, { x: undefined }), 'SIGNING_KEYS.active: x and y required'],
        ['an active key with a numeric y', (doc) => active(doc, { y: 1 }), 'SIGNING_KEYS.active: x and y required'],
        ['an active key without d', (doc) => ({ ...doc, active: publicPart(doc.active) }), 'SIGNING_KEYS.active: private key required'],
        ['an active key with an empty d', (doc) => active(doc, { d: '' }), 'SIGNING_KEYS.active: private key required'],
        ['an active key with a numeric d', (doc) => active(doc, { d: 7 }), 'SIGNING_KEYS.active: private key required'],
        ['an active key for ES384', (doc) => active(doc, { alg: 'ES384' }), 'SIGNING_KEYS.active: alg must be ES256'],
        ['an active key for encryption', (doc) => active(doc, { use: 'enc' }), 'SIGNING_KEYS.active: use must be sig'],
        ['an active kid that is not the thumbprint', (doc) => active(doc, { kid: 'k1' }), 'SIGNING_KEYS.active: kid must equal the key thumbprint'],
        [
            "an active kid that is a retired key's thumbprint",
            async (doc) => active(doc, { kid: await calculateJwkThumbprint(doc.retired[0]) }),
            'SIGNING_KEYS.active: kid must equal the key thumbprint',
        ],
        ['an active key with a point off the curve', (doc) => active(doc, { x: doc.active.y }), 'SIGNING_KEYS.active: not a valid P-256 key'],
        ['an active key with a short x', (doc) => active(doc, { x: 'AAAA' }), 'SIGNING_KEYS.active: not a valid P-256 key'],
        // workerd refuses this at import; runtimes that do not are covered by the faults below
        ['an active d of another key', async (doc) => active(doc, { d: (await another()).d }), 'SIGNING_KEYS.active: not a valid P-256 key'],
        ['an active d that is not base64url', (doc) => active(doc, { d: `${doc.active.d.slice(1)}*` }), 'SIGNING_KEYS.active: not a valid P-256 key'],
        ['retired keys that are not an array', (doc) => ({ ...doc, retired: doc.retired[0] }), 'SIGNING_KEYS.retired: must be an array'],
        ['retired keys that are null', (doc) => ({ ...doc, retired: null }), 'SIGNING_KEYS.retired: must be an array'],
        ['a retired key that is null', (doc) => retired(doc, doc.retired[0], null), 'SIGNING_KEYS.retired[1]: must be a JWK object'],
        [
            'a private key in retired',
            async (doc) => retired(doc, doc.retired[0], await another()),
            'SIGNING_KEYS.retired[1]: private key not allowed',
        ],
        ['the active private key in retired', (doc) => retired(doc, doc.active), 'SIGNING_KEYS.retired[0]: private key not allowed'],
        ['a retired key with a null d', (doc) => retired(doc, { ...doc.retired[0], d: null }), 'SIGNING_KEYS.retired[0]: private key not allowed'],
        ['a retired P-384 key', async (doc) => retired(doc, publicPart(await p384PrivateJwk())), 'SIGNING_KEYS.retired[0]: must use curve P-256'],
        ['a retired RSA key', (doc) => retired(doc, { kty: 'RSA', n: 'AQAB', e: 'AQAB' }), 'SIGNING_KEYS.retired[0]: must be an EC key'],
        [
            'a retired kid that is not the thumbprint',
            (doc) => retired(doc, { ...doc.retired[0], kid: 'old' }),
            'SIGNING_KEYS.retired[0]: kid must equal the key thumbprint',
        ],
        ['a retired key for ES512', (doc) => retired(doc, { ...doc.retired[0], alg: 'ES512' }), 'SIGNING_KEYS.retired[0]: alg must be ES256'],
        [
            'a retired key with a point off the curve',
            (doc) => retired(doc, { ...doc.retired[0], y: doc.retired[0].x }),
            'SIGNING_KEYS.retired[0]: not a valid P-256 key',
        ],
        ['the active key repeated in retired', (doc) => retired(doc, publicPart(doc.active)), 'SIGNING_KEYS.retired[0]: repeats an earlier key'],
        ['a retired key listed twice', (doc) => retired(doc, doc.retired[0], doc.retired[0]), 'SIGNING_KEYS.retired[1]: repeats an earlier key'],
    ]

    it.each(CASES)('refuses %s', async (_, edit, message) => {
        const secret = await bridgeSigningKeys(1)
        const doc = await edit({ active: secret.active, retired: secret.retired })
        const error = await rejection(JSON.stringify(doc))
        expect(error.name).toBe('KeyError')
        expect(error.message).toBe(message)
        expect(error.cause).toBeUndefined()
        for (const d of privateValues(doc)) for (const run of runsOf(d)) expect(error.message).not.toContain(run)
    })

    it('refuses invalid JSON without quoting it, although JSON.parse would', async () => {
        const { active } = await bridgeSigningKeys()
        const json = `{"active": {"kty": "EC", "crv": "P-256", "x": "${active.x}", "y": "${active.y}", "d": x${active.d}}}`
        const native = (() => {
            try {
                JSON.parse(json)
            } catch (caught) {
                return (caught as Error).message
            }
        })()
        expect(native).toContain(active.d!.slice(0, 6))
        const error = await rejection(json)
        expect(error.message).toBe('SIGNING_KEYS: invalid JSON')
        expect(error.cause).toBeUndefined()
        for (const run of runsOf(active.d!)) expect(error.message).not.toContain(run)
    })

    it('refuses a __proto__ member, which JSON.parse makes an own key', async () => {
        const { active } = await bridgeSigningKeys()
        const error = await rejection(`{"active": ${JSON.stringify(active)}, "__proto__": {"retired": []}}`)
        expect(error.message).toBe('SIGNING_KEYS: only active and retired are allowed')
    })

    it.each(['', '{', 'undefined', '{"active": {}', `{"active": 'x'}`])('refuses %j as invalid JSON', async (json) => {
        expect((await rejection(json)).message).toBe('SIGNING_KEYS: invalid JSON')
    })

    it('refuses a truncated secret without quoting it', async () => {
        const { json, active } = await bridgeSigningKeys(1)
        for (const cut of [json.length - 1, json.indexOf(active.d!) + 10]) {
            const error = await rejection(json.slice(0, cut))
            expect(error.message).toBe('SIGNING_KEYS: invalid JSON')
            for (const run of runsOf(active.d!)) expect(error.message).not.toContain(run)
        }
    })
})

// Faults inside WebCrypto and jose, whose error text may quote the key
describe('importSigningKeys faults', () => {
    const subtle = crypto.subtle
    const digest = subtle.digest.bind(subtle)

    afterEach(() => {
        vi.restoreAllMocks()
    })

    // Unlike workerd, a runtime that imports a private JWK without checking d against x and y
    function acceptMismatchedImports(owner: JsonWebKey) {
        const importKey = subtle.importKey.bind(subtle)
        vi.spyOn(subtle, 'importKey').mockImplementation(((format: any, keyData: any, ...rest: any[]) => {
            const own = format === 'jwk' && keyData.d === owner.d ? { ...keyData, x: owner.x, y: owner.y } : keyData
            return (importKey as any)(format, own, ...rest)
        }) as typeof subtle.importKey)
    }

    it('refuses an active d of another key even where the import does not check it', async () => {
        const [secret, owner] = await Promise.all([bridgeSigningKeys(1), bridgeSigningKeys()])
        acceptMismatchedImports(owner.active)
        const json = JSON.stringify({ active: { ...secret.active, d: owner.active.d }, retired: secret.retired })
        const error = await rejection(json)
        expect(error.message).toBe('SIGNING_KEYS.active: private key does not match x and y')
        for (const run of runsOf(owner.active.d!)) expect(error.message).not.toContain(run)
    })

    it('still accepts a matching key where the import does not check it', async () => {
        const secret = await bridgeSigningKeys(1)
        acceptMismatchedImports(secret.active)
        expect((await importSigningKeys(secret.json)).jwks.keys).toHaveLength(2)
    })

    it('turns a failure to sign the key check into a fixed KeyError', async () => {
        const secret = await bridgeSigningKeys()
        vi.spyOn(subtle, 'sign').mockRejectedValue(new Error(`cannot sign with ${secret.active.d}`))
        const error = await rejection(secret.json)
        expect(error.message).toBe('SIGNING_KEYS.active: not a valid P-256 key')
        for (const run of runsOf(secret.active.d!)) expect(error.message).not.toContain(run)
    })

    it.each([
        ['active', 0, 'SIGNING_KEYS.active: not a valid P-256 key'],
        ['retired', 1, 'SIGNING_KEYS.retired[0]: not a valid P-256 key'],
    ])('turns a thumbprint failure of the %s key into a fixed KeyError', async (_, passing, message) => {
        const secret = await bridgeSigningKeys(1)
        const spy = vi.spyOn(subtle, 'digest')
        for (let call = 0; call < passing; call++) spy.mockImplementationOnce(digest)
        spy.mockRejectedValueOnce(new Error(`digest failed for ${secret.active.d}`))
        const error = await rejection(secret.json)
        expect(error.message).toBe(message)
        expect(error.cause).toBeUndefined()
        for (const run of runsOf(secret.active.d!)) expect(error.message).not.toContain(run)
    })
})
