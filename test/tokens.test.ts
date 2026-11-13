import { createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JWTVerifyOptions } from 'jose'
import { describe, expect, it } from 'vitest'
import { parseConfig } from '../src/config'
import { importSigningKeys } from '../src/keys'
import { mintAccessToken, mintEventToken } from '../src/tokens'
import type { Config, EventType, Profile, SigningKeys } from '../src/types'
import { casdoorConfig, clerkConfig, clerkConfigJson } from './helpers/config'
import { bridgeSigningKeys } from './helpers/keys'

// Far from the real clock, so a claim taken from the clock instead of nowSec would show
const NOW = 1_000_000_000
const USER = 'd4b7bc25-004f-5965-a191-6da1608b6639'
const JTI = '00000000-0000-4000-8000-000000000001'
const PROFILE: Profile = {
    email: 'ada@acme.example',
    phoneNumber: '+14155550123',
    name: 'Ada Lovelace',
    picture: 'https://img.acme.example/ada.png',
}
const PROFILE_CLAIMS = {
    email: 'ada@acme.example',
    phone_number: '+14155550123',
    name: 'Ada Lovelace',
    picture: 'https://img.acme.example/ada.png',
}

async function setup(config: Config = parseConfig(clerkConfigJson)): Promise<{ keys: SigningKeys; config: Config }> {
    return { keys: await importSigningKeys((await bridgeSigningKeys(1)).json), config }
}

async function verify(token: string, keys: SigningKeys, options: JWTVerifyOptions) {
    return jwtVerify(token, createLocalJWKSet(keys.jwks), { algorithms: ['ES256'], currentDate: new Date(NOW * 1000), ...options })
}

// Each would pass jose's own check, which only asks for a finite number, or fail it with jose's message
const NOT_INTEGERS: [string, unknown][] = [
    ['a fraction', NOW + 0.5],
    ['a negative fraction', -0.5],
    ['NaN', NaN],
    ['Infinity', Infinity],
    ['-Infinity', -Infinity],
    ['a numeric string', String(NOW)],
    ['null', null],
    ['undefined', undefined],
    ['a Number object', new Number(NOW)],
]

async function rejection(mint: Promise<string>): Promise<unknown> {
    return mint.then(
        () => undefined,
        (caught: unknown) => caught,
    )
}

function withoutRegion(): Config {
    const { region, ...doc } = clerkConfig()
    void region
    return parseConfig(JSON.stringify(doc))
}

describe('mintAccessToken', () => {
    it('signs a token that verifies against the JWKS, with exactly the header and claims of the profile', async () => {
        const { keys, config } = await setup()
        const token = await mintAccessToken(keys, config, 'acme', { userId: USER, idpId: 'clerk-acme', profile: PROFILE }, NOW, JTI)
        const { protectedHeader, payload } = await verify(token, keys, { typ: 'at+jwt', issuer: 'https://id.acme.example', audience: 'acme' })
        expect(protectedHeader).toStrictEqual({ alg: 'ES256', typ: 'at+jwt', kid: keys.kid })
        expect(payload).toStrictEqual({
            iss: 'https://id.acme.example',
            sub: USER,
            aud: 'acme',
            client_id: 'acme',
            iat: NOW,
            exp: NOW + 900,
            jti: JTI,
            idp: 'clerk-acme',
            region: 'us',
            ...PROFILE_CLAIMS,
        })
    })

    it('carries no region when none is configured', async () => {
        const { keys, config } = await setup(withoutRegion())
        const token = await mintAccessToken(keys, config, 'acme', { userId: USER, idpId: 'clerk-acme', profile: {} }, NOW, JTI)
        const { payload } = await verify(token, keys, { typ: 'at+jwt' })
        expect(payload).toStrictEqual({
            iss: 'https://id.acme.example',
            sub: USER,
            aud: 'acme',
            client_id: 'acme',
            iat: NOW,
            exp: NOW + 900,
            jti: JTI,
            idp: 'clerk-acme',
        })
    })

    it('carries only the profile claims that are known', async () => {
        const { keys, config } = await setup()
        const token = await mintAccessToken(keys, config, 'acme', { userId: USER, idpId: 'clerk-acme', profile: { name: 'Ada' } }, NOW, JTI)
        const { payload } = await verify(token, keys, { typ: 'at+jwt' })
        expect(payload).toMatchObject({ name: 'Ada' })
        for (const claim of ['email', 'email_verified', 'phone_number', 'phone_number_verified', 'phoneNumber', 'picture', 'scope']) {
            expect(payload).not.toHaveProperty(claim)
        }
    })

    it('carries only the claims it maps, whatever else the profile object holds', async () => {
        const { keys, config } = await setup()
        const profile = { ...PROFILE, email_verified: true, scope: 'admin' } as Profile
        const token = await mintAccessToken(keys, config, 'acme', { userId: USER, idpId: 'clerk-acme', profile }, NOW, JTI)
        const { payload } = await verify(token, keys, { typ: 'at+jwt' })
        expect(Object.keys(payload).sort()).toEqual(
            ['aud', 'client_id', 'email', 'exp', 'iat', 'idp', 'iss', 'jti', 'name', 'phone_number', 'picture', 'region', 'sub'],
        )
    })

    it('takes the issuer, region and lifetime from the configuration and the audience from the product', async () => {
        const doc = { ...casdoorConfig(), tokenTtlSeconds: 3600 }
        const { keys, config } = await setup(parseConfig(JSON.stringify(doc)))
        const token = await mintAccessToken(keys, config, 'globex', { userId: USER, idpId: 'casdoor', profile: {} }, NOW, JTI)
        const { payload } = await verify(token, keys, { typ: 'at+jwt', issuer: 'https://id.cn.acme.example', audience: 'globex' })
        expect(payload).toMatchObject({
            iss: 'https://id.cn.acme.example',
            aud: 'globex',
            client_id: 'globex',
            idp: 'casdoor',
            region: 'cn',
            exp: NOW + 3600,
        })
    })

    it('uses nowSec for the times and never the clock', async () => {
        const { keys, config } = await setup()
        const token = await mintAccessToken(keys, config, 'acme', { userId: USER, idpId: 'clerk-acme', profile: {} }, NOW, JTI)
        const { payload } = await verify(token, keys, { typ: 'at+jwt' })
        expect([payload.iat, payload.exp]).toEqual([NOW, NOW + 900])
        await expect(jwtVerify(token, createLocalJWKSet(keys.jwks))).rejects.toMatchObject({ code: 'ERR_JWT_EXPIRED' })
    })

    it('is signed by the active key only', async () => {
        const { keys, config } = await setup()
        const token = await mintAccessToken(keys, config, 'acme', { userId: USER, idpId: 'clerk-acme', profile: {} }, NOW, JTI)
        expect(decodeProtectedHeader(token).kid).toBe(keys.jwks.keys[0]!.kid)
        const retiredOnly = { keys: keys.jwks.keys.slice(1) }
        await expect(jwtVerify(token, createLocalJWKSet(retiredOnly), { currentDate: new Date(NOW * 1000) })).rejects.toMatchObject({
            code: 'ERR_JWKS_NO_MATCHING_KEY',
        })
    })

    it.each(NOT_INTEGERS)('rejects %s as nowSec with a TypeError', async (_, nowSec) => {
        const { keys, config } = await setup()
        const identity = { userId: USER, idpId: 'clerk-acme', profile: {} }
        const error = await rejection(Promise.resolve().then(() => mintAccessToken(keys, config, 'acme', identity, nowSec as number, JTI)))
        expect(error).toBeInstanceOf(TypeError)
        expect((error as TypeError).message).toBe('nowSec must be an integer')
        expect(() => mintAccessToken(keys, config, 'acme', identity, nowSec as number, JTI).catch(() => undefined)).not.toThrow()
    })
})

describe('mintEventToken', () => {
    const EVENT_JTI = 'f261a66f-806c-5d47-ad4c-991aae2bfd52'
    const TXN = 'msg_2pXk8AbCdEfGhIjKlMnOpQrStUv'

    async function mint(type: EventType, profile: Profile, config?: Config) {
        const { keys, config: used } = await setup(config)
        const token = await mintEventToken(keys, used, 'acme', { jti: EVENT_JTI, txn: TXN, userId: USER, type, profile }, NOW)
        return { keys, token, ...(await verify(token, keys, { typ: 'secevent+jwt', issuer: 'https://id.acme.example', audience: 'acme' })) }
    }

    function claims(events: Record<string, unknown>) {
        return { iss: 'https://id.acme.example', aud: 'acme', iat: NOW, jti: EVENT_JTI, txn: TXN, sub: USER, events }
    }

    it.each(['user-created', 'user-updated'] as const)('signs a %s event with exactly the header and claims of the profile', async (type) => {
        const { keys, protectedHeader, payload } = await mint(type, PROFILE)
        expect(protectedHeader).toStrictEqual({ alg: 'ES256', typ: 'secevent+jwt', kid: keys.kid })
        expect(payload).toStrictEqual(claims({ [`urn:identity-bridge:event:${type}`]: PROFILE_CLAIMS }))
    })

    it('signs a user-deleted event with an empty payload, whatever the profile', async () => {
        const { payload } = await mint('user-deleted', PROFILE)
        expect(payload).toStrictEqual(claims({ 'urn:identity-bridge:event:user-deleted': {} }))
    })

    it('carries only the profile claims that are known', async () => {
        const { payload } = await mint('user-created', { email: 'ada@acme.example' })
        expect(payload.events).toStrictEqual({ 'urn:identity-bridge:event:user-created': { email: 'ada@acme.example' } })
        expect((await mint('user-updated', {})).payload.events).toStrictEqual({ 'urn:identity-bridge:event:user-updated': {} })
    })

    it('carries no exp, so it verifies at any later time', async () => {
        const { keys, token, payload } = await mint('user-created', PROFILE)
        expect(payload).not.toHaveProperty('exp')
        await jwtVerify(token, createLocalJWKSet(keys.jwks), { currentDate: new Date((NOW + 10 * 365 * 86400) * 1000) })
    })

    it('carries no region, client_id or idp, even when a region is configured', async () => {
        const { payload } = await mint('user-created', PROFILE, parseConfig(clerkConfigJson))
        for (const claim of ['region', 'client_id', 'idp', 'exp', 'nbf']) expect(payload).not.toHaveProperty(claim)
        const { payload: without } = await mint('user-created', PROFILE, withoutRegion())
        expect(without).toStrictEqual(payload)
    })

    it('uses nowSec for iat and never the clock', async () => {
        const { payload } = await mint('user-deleted', {})
        expect(payload.iat).toBe(NOW)
    })

    it.each(NOT_INTEGERS)('rejects %s as nowSec with a TypeError', async (_, nowSec) => {
        const { keys, config } = await setup()
        const event = { jti: EVENT_JTI, txn: TXN, userId: USER, type: 'user-created' as const, profile: {} }
        const error = await rejection(Promise.resolve().then(() => mintEventToken(keys, config, 'acme', event, nowSec as number)))
        expect(error).toBeInstanceOf(TypeError)
        expect((error as TypeError).message).toBe('nowSec must be an integer')
        expect(() => mintEventToken(keys, config, 'acme', event, nowSec as number).catch(() => undefined)).not.toThrow()
    })
})
