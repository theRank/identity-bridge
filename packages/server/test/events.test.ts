import { decodeJwt } from 'jose'
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { START_MS } from '../../../test/helpers/deps'
import { NOW_SEC } from '../../../test/helpers/idp'
import { BridgeTokenError, createVerifier, type BridgeTokenErrorReason } from '../src/index'
import { ADA, bridge, generateKeys, ISSUER, rejection, resign, type ClerkEventType, type Keys } from './bridge'

const CREATED = 'urn:identity-bridge:event:user-created'
const UPDATED = 'urn:identity-bridge:event:user-updated'
const DELETED = 'urn:identity-bridge:event:user-deleted'
const PROFILE = { email: ADA.email, phoneNumber: ADA.phoneNumber, name: ADA.name, picture: ADA.picture }

let keys: Keys

beforeAll(async () => {
    keys = await generateKeys()
})

beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(START_MS)
})

afterEach(() => {
    vi.useRealTimers()
})

function setup(options: { issuer?: string; audience?: string } = {}) {
    const real = bridge(keys)
    const verifier = createVerifier({ issuer: options.issuer ?? ISSUER, audience: options.audience ?? 'acme', fetch: real.fetch })
    return { real, verifier }
}

async function reason(pending: Promise<unknown>): Promise<BridgeTokenErrorReason> {
    const error = await rejection(pending)
    expect(error).toBeInstanceOf(BridgeTokenError)
    return (error as BridgeTokenError).reason
}

describe('verifyEvent', () => {
    it.each([
        ['user.created', 'user-created', PROFILE],
        ['user.updated', 'user-updated', PROFILE],
        ['user.deleted', 'user-deleted', {}],
    ] satisfies [ClerkEventType, string, object][])('gives the %s event the bridge relayed as %s', async (clerkType, type, profile) => {
        const { real, verifier } = setup()
        const token = await real.eventToken(clerkType)
        const claims = decodeJwt(token)
        expect(await verifier.verifyEvent(token)).toStrictEqual({ jti: claims.jti, type, userId: claims.sub, profile, issuedAt: NOW_SEC })
        expect(claims.jti).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    })

    it('accepts an event at any later time, as events carry no exp', async () => {
        const { real, verifier } = setup()
        const token = await real.eventToken('user.created')
        expect(decodeJwt(token)).not.toHaveProperty('exp')
        vi.setSystemTime(START_MS + 30 * 86_400_000)
        expect(await verifier.verifyEvent(token)).toMatchObject({ type: 'user-created' })
    })

    it('accepts typ application/secevent+jwt', async () => {
        const { real, verifier } = setup()
        const token = await resign(keys, await real.eventToken('user.updated'), { header: { typ: 'application/secevent+jwt' } })
        expect(await verifier.verifyEvent(token)).toMatchObject({ type: 'user-updated' })
    })

    it('leaves out the profile members an event does not carry', async () => {
        const { real, verifier } = setup()
        const token = await resign(keys, await real.eventToken('user.created'), { claims: { events: { [CREATED]: { name: ADA.name } } } })
        expect(await verifier.verifyEvent(token)).toMatchObject({ profile: { name: ADA.name } })
    })

    it('gives a profile updated_at as updatedAt', async () => {
        const { real, verifier } = setup()
        const token = await resign(keys, await real.eventToken('user.updated'), { claims: { events: { [UPDATED]: { email: ADA.email, updated_at: NOW_SEC - 5 } } } })
        expect(await verifier.verifyEvent(token)).toMatchObject({ profile: { email: ADA.email, updatedAt: NOW_SEC - 5 } })
    })

    describe('reasons', () => {
        it('rejects an empty body as missing', async () => {
            const { verifier } = setup()
            expect(await reason(verifier.verifyEvent(''))).toBe('missing')
        })

        it('rejects a body that is not a JWT as malformed', async () => {
            const { verifier } = setup()
            expect(await reason(verifier.verifyEvent('{"events": {}}'))).toBe('malformed')
        })

        it('rejects an access token as wrong_type', async () => {
            const { real, verifier } = setup()
            expect(await reason(verifier.verifyEvent(await real.accessToken()))).toBe('wrong_type')
        })

        it('rejects an event of another issuer as wrong_issuer', async () => {
            const { real, verifier } = setup({ issuer: 'https://id.cn.acme.example' })
            expect(await reason(verifier.verifyEvent(await real.eventToken('user.created')))).toBe('wrong_issuer')
        })

        it('rejects an event for another product as wrong_audience', async () => {
            const { real, verifier } = setup({ audience: 'globex' })
            expect(await reason(verifier.verifyEvent(await real.eventToken('user.created')))).toBe('wrong_audience')
        })

        it('rejects an event whose signature does not verify as bad_signature', async () => {
            const { real, verifier } = setup()
            const [header, payload] = (await real.eventToken('user.created')).split('.')
            const otherSignature = (await real.eventToken('user.deleted')).split('.')[2]
            expect(await reason(verifier.verifyEvent(`${header}.${payload}.${otherSignature}`))).toBe('bad_signature')
        })

        it('rejects an event with an exp in the past as expired', async () => {
            const { real, verifier } = setup()
            const token = await resign(keys, await real.eventToken('user.created'), { claims: { exp: NOW_SEC - 3600 } })
            expect(await reason(verifier.verifyEvent(token))).toBe('expired')
        })

        it.each([
            ['no jti', { jti: undefined }],
            ['a jti that is not a string', { jti: 42 }],
            ['no iat', { iat: undefined }],
            ['no sub', { sub: undefined }],
            ['a sub that is not a lowercase UUID', { sub: 'USER_2PXKLM4NQR7ST9VW1XY3ZB5CD8F' }],
            ['no events', { events: undefined }],
            ['events that are not an object', { events: [CREATED] }],
            ['events that are null', { events: null }],
            ['no event', { events: {} }],
            ['two events', { events: { [CREATED]: {}, [DELETED]: {} } }],
            ['an unknown event type', { events: { 'urn:identity-bridge:event:user-merged': {} } }],
            ['an event type of another profile', { events: { 'https://schemas.openid.net/secevent/risc/event-type/account-disabled': {} } }],
            ['an event payload that is not an object', { events: { [UPDATED]: 'Ada' } }],
            ['a profile member that is not a string', { events: { [UPDATED]: { email: 42 } } }],
            ['a profile updated_at that is not a number', { events: { [UPDATED]: { updated_at: '1760000000' } } }],
        ])('rejects %s as invalid_claims', async (_, claims) => {
            const { real, verifier } = setup()
            const token = await resign(keys, await real.eventToken('user.updated'), { claims })
            expect(await reason(verifier.verifyEvent(token))).toBe('invalid_claims')
        })
    })

    it('throws a BridgeTokenError without cause that quotes no claim', async () => {
        const { real, verifier } = setup({ audience: 'globex' })
        const token = await real.eventToken('user.created')
        const error = await rejection(verifier.verifyEvent(token))
        expect(error).toMatchObject({ name: 'BridgeTokenError', reason: 'wrong_audience' })
        expect(error).not.toHaveProperty('cause')
        const shown = [String(error), (error as Error).stack ?? '', JSON.stringify(error)].join('\n')
        for (const value of [token, ADA.email, ADA.phoneNumber, ADA.name, decodeJwt(token).sub as string]) expect(shown).not.toContain(value)
    })

    it('verifies access tokens and events with one verifier and one JWKS fetch', async () => {
        const { real, verifier } = setup()
        await verifier.verifyEvent(await real.eventToken('user.created'))
        await verifier.verifyAccessToken(await real.accessToken())
        expect(real.fetched).toHaveLength(1)
    })
})
