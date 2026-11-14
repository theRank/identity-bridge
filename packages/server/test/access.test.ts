import { decodeJwt } from 'jose'
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { START_MS } from '../../../test/helpers/deps'
import { NOW_SEC, unsignedToken } from '../../../test/helpers/idp'
import { BridgeTokenError, createVerifier, type BridgeTokenErrorReason } from '../src/index'
import { ADA, bridge, generateKeys, ISSUER, JWKS_URL, rejection, resign, until, type Bridge, type Keys } from './bridge'

const EXP_MS = START_MS + 900_000

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
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
})

interface Setup {
    real: Bridge
    verifier: ReturnType<typeof createVerifier>
}

function setup(options: { issuer?: string; audience?: string; clockToleranceSeconds?: number; fetch?: typeof fetch } = {}): Setup {
    const real = bridge(keys)
    const { issuer = ISSUER, audience = 'acme', fetch = real.fetch, clockToleranceSeconds } = options
    const verifier = createVerifier({ issuer, audience, fetch, ...(clockToleranceSeconds === undefined ? {} : { clockToleranceSeconds }) })
    return { real, verifier }
}

async function reason(pending: Promise<unknown>): Promise<BridgeTokenErrorReason> {
    const error = await rejection(pending)
    expect(error).toBeInstanceOf(BridgeTokenError)
    return (error as BridgeTokenError).reason
}

describe('createVerifier', () => {
    it.each([61, -1, Number.NaN, 3600, Infinity])('rejects clockToleranceSeconds %s, as bridge tokens allow at most 60 s', (clockToleranceSeconds) => {
        expect(() => createVerifier({ issuer: ISSUER, audience: 'acme', clockToleranceSeconds })).toThrow(RangeError)
    })

    // What a value read from the environment without parsing looks like
    it.each(['30', null, true])('rejects clockToleranceSeconds %j that is not a number', (clockToleranceSeconds) => {
        expect(() => createVerifier({ issuer: ISSUER, audience: 'acme', clockToleranceSeconds: clockToleranceSeconds as unknown as number })).toThrow(TypeError)
    })

    it.each([0, 30, 60, undefined])('accepts clockToleranceSeconds %s', (clockToleranceSeconds) => {
        expect(() => createVerifier({ issuer: ISSUER, audience: 'acme', clockToleranceSeconds })).not.toThrow()
    })

    // An unset environment variable gives undefined; jose would then skip the aud check and accept every product's
    // tokens
    it.each([undefined, '', 42, null, ['acme']])('rejects the audience %j', (audience) => {
        expect(() => createVerifier({ issuer: ISSUER, audience: audience as unknown as string })).toThrow(TypeError)
    })

    it.each([undefined, '', 42, null])('rejects the issuer %j', (issuer) => {
        expect(() => createVerifier({ issuer: issuer as unknown as string, audience: 'acme' })).toThrow(TypeError)
    })

    it('rejects missing options', () => {
        expect(() => createVerifier(undefined as unknown as Parameters<typeof createVerifier>[0])).toThrow(TypeError)
    })
})

describe('verifyAccessToken', () => {
    it('gives the user of a token the bridge issued', async () => {
        const { real, verifier } = setup()
        const token = await real.accessToken()
        expect(await verifier.verifyAccessToken(token)).toStrictEqual({
            userId: decodeJwt(token).sub,
            email: ADA.email,
            phoneNumber: ADA.phoneNumber,
            name: ADA.name,
            picture: ADA.picture,
            region: 'us',
            expiresAt: NOW_SEC + 900,
        })
        expect(decodeJwt(token).sub).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    })

    it('leaves out the claims a token does not carry', async () => {
        const { real, verifier } = setup()
        const token = await real.accessToken({ email: undefined, name: undefined, picture: undefined, phone_number: undefined })
        expect(await verifier.verifyAccessToken(token)).toStrictEqual({ userId: decodeJwt(token).sub, region: 'us', expiresAt: NOW_SEC + 900 })
    })

    it('does not expose the idp claim', async () => {
        const { real, verifier } = setup()
        const token = await real.accessToken()
        expect(decodeJwt(token).idp).toBe('clerk-acme')
        expect(await verifier.verifyAccessToken(token)).not.toHaveProperty('idp')
    })

    it('fetches the JWKS from the issuer once and keeps it', async () => {
        const { real, verifier } = setup()
        await verifier.verifyAccessToken(await real.accessToken())
        await verifier.verifyAccessToken(await real.accessToken())
        expect(real.fetched).toEqual([JWKS_URL])
    })

    it('accepts typ application/at+jwt', async () => {
        const { real, verifier } = setup()
        const token = await resign(keys, await real.accessToken(), { header: { typ: 'application/at+jwt' } })
        expect(await verifier.verifyAccessToken(token)).toMatchObject({ userId: decodeJwt(token).sub })
    })

    describe('time', () => {
        it('accepts a token up to 60 s after it expired, by default', async () => {
            const { real, verifier } = setup()
            const token = await real.accessToken()
            vi.setSystemTime(EXP_MS + 59_000)
            expect(await verifier.verifyAccessToken(token)).toMatchObject({ expiresAt: NOW_SEC + 900 })
            vi.setSystemTime(EXP_MS + 60_000)
            expect(await reason(verifier.verifyAccessToken(token))).toBe('expired')
        })

        it('applies clockToleranceSeconds', async () => {
            const { real, verifier } = setup({ clockToleranceSeconds: 0 })
            const token = await real.accessToken()
            vi.setSystemTime(EXP_MS - 1000)
            await verifier.verifyAccessToken(token)
            vi.setSystemTime(EXP_MS)
            expect(await reason(verifier.verifyAccessToken(token))).toBe('expired')
        })

        it('rejects a token not yet valid as invalid_claims', async () => {
            const { real, verifier } = setup()
            const token = await resign(keys, await real.accessToken(), { claims: { nbf: NOW_SEC + 120 } })
            expect(await reason(verifier.verifyAccessToken(token))).toBe('invalid_claims')
        })
    })

    describe('reasons', () => {
        it.each(['', undefined, null])('rejects the token %j as missing', async (token) => {
            const { verifier, real } = setup()
            expect(await reason(verifier.verifyAccessToken(token as string))).toBe('missing')
            expect(real.fetched).toEqual([])
        })

        it.each([
            ['not a JWT', () => 'not-a-jwt'],
            ['three parts that are not base64url JSON', () => 'a.b.c'],
            ['a claims set that is not JSON', (token: string) => resign(keys, token, { payload: 'not json' })],
            ['an exp that is not a number', (token: string) => resign(keys, token, { claims: { exp: String(NOW_SEC + 900) } })],
            ['an iat that is not a number', (token: string) => resign(keys, token, { claims: { iat: 'now' } })],
            ['an unsupported crit extension', (token: string) => resign(keys, token, { header: { crit: ['x-ext'], 'x-ext': true } })],
        ])('rejects %s as malformed', async (_, make) => {
            const { real, verifier } = setup()
            expect(await reason(verifier.verifyAccessToken(await make(await real.accessToken())))).toBe('malformed')
        })

        it.each(['HS256', 'RS256', 'ES384', 'none'])('rejects alg %s as wrong_algorithm', async (alg) => {
            const { real, verifier } = setup()
            const claims = decodeJwt(await real.accessToken())
            const token = unsignedToken({ alg, typ: 'at+jwt', kid: keys.bridge.kid }, claims, 'c2lnbmF0dXJl')
            expect(await reason(verifier.verifyAccessToken(token))).toBe('wrong_algorithm')
        })

        it('rejects a kid the JWKS does not publish as unknown_key', async () => {
            const { real, verifier } = setup()
            const token = await resign(keys, await real.accessToken(), { header: { kid: 'retired-long-ago' } })
            expect(await reason(verifier.verifyAccessToken(token))).toBe('unknown_key')
        })

        it('rejects a token without kid, which both published keys match, as unknown_key', async () => {
            const { real, verifier } = setup()
            const token = await resign(keys, await real.accessToken(), { header: { kid: undefined } })
            expect(await reason(verifier.verifyAccessToken(token))).toBe('unknown_key')
        })

        it('rejects a token whose signature does not verify as bad_signature', async () => {
            const { real, verifier } = setup()
            const [header, payload] = (await real.accessToken()).split('.')
            const otherSignature = (await real.accessToken({ name: 'Grace Hopper' })).split('.')[2]
            expect(await reason(verifier.verifyAccessToken(`${header}.${payload}.${otherSignature}`))).toBe('bad_signature')
        })

        it.each([
            ['an event token', (real: Bridge) => real.eventToken('user.created')],
            ['typ JWT', async (real: Bridge) => resign(keys, await real.accessToken(), { header: { typ: 'JWT' } })],
            ['no typ', async (real: Bridge) => resign(keys, await real.accessToken(), { header: { typ: undefined } })],
        ])('rejects %s as wrong_type', async (_, make) => {
            const { real, verifier } = setup()
            expect(await reason(verifier.verifyAccessToken(await make(real)))).toBe('wrong_type')
        })

        it('rejects a token of another issuer as wrong_issuer', async () => {
            const { real, verifier } = setup({ issuer: 'https://id.cn.acme.example' })
            expect(await reason(verifier.verifyAccessToken(await real.accessToken()))).toBe('wrong_issuer')
        })

        it('rejects a token without iss as wrong_issuer', async () => {
            const { real, verifier } = setup()
            const token = await resign(keys, await real.accessToken(), { claims: { iss: undefined } })
            expect(await reason(verifier.verifyAccessToken(token))).toBe('wrong_issuer')
        })

        it('rejects a token of another product as wrong_audience', async () => {
            const { real, verifier } = setup({ audience: 'globex' })
            expect(await reason(verifier.verifyAccessToken(await real.accessToken()))).toBe('wrong_audience')
        })

        it('rejects a token without aud as wrong_audience', async () => {
            const { real, verifier } = setup()
            const token = await resign(keys, await real.accessToken(), { claims: { aud: undefined } })
            expect(await reason(verifier.verifyAccessToken(token))).toBe('wrong_audience')
        })

        it.each([
            ['no exp', { exp: undefined }],
            ['no iat', { iat: undefined }],
            ['no sub', { sub: undefined }],
            ['a sub that is not a UUID', { sub: 'user_2pXkLm4NqR7sT9vW1xY3zB5cD8f' }],
            ['an uppercase UUID sub', { sub: 'D4B7BC25-004F-5965-A191-6DA1608B6639' }],
            ['a UUID sub without hyphens', { sub: 'd4b7bc25004f5965a1916da1608b6639' }],
            ['a sub that is not a string', { sub: 42 }],
            ['an email that is not a string', { email: ['ada@acme.example'] }],
            ['a region that is not a string', { region: 1 }],
        ])('rejects %s as invalid_claims', async (_, claims) => {
            const { real, verifier } = setup()
            const token = await resign(keys, await real.accessToken(), { claims })
            expect(await reason(verifier.verifyAccessToken(token))).toBe('invalid_claims')
        })
    })

    describe('jwks_unavailable', () => {
        const token = (keys: Keys) => bridge(keys).accessToken()

        it.each([
            ['a rejected fetch', () => Promise.reject(new TypeError('Network connection lost.'))],
            ['a fetch that throws', () => {
                throw new TypeError('fetch failed')
            }],
            ['a 500', () => new Response('<html>down</html>', { status: 500 })],
            ['a 304', () => new Response(null, { status: 304 })],
            ['a body that is not JSON', () => new Response('<html>Sign in</html>')],
            ['a JSON body that is not an object', () => Response.json([])],
            ['a body that is not a JWKS', () => Response.json({ keys: 'none' })],
            ['a key that cannot be imported', () => Response.json({ keys: [{ kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'AAAA', kid: keys.bridge.kid, alg: 'ES256', use: 'sig' }] })],
        ])('rejects when the JWKS fetch gives %s', async (_, respond) => {
            const verifier = createVerifier({ issuer: ISSUER, audience: 'acme', fetch: (async () => respond()) as unknown as typeof fetch })
            expect(await reason(verifier.verifyAccessToken(await token(keys)))).toBe('jwks_unavailable')
        })

        it('rejects when the JWKS fetch has not answered after 5 s', async () => {
            const minted = await token(keys)
            vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] })
            vi.setSystemTime(START_MS)
            // Never answers, whatever its signal does
            const verifier = createVerifier({ issuer: ISSUER, audience: 'acme', fetch: (() => new Promise<never>(() => {})) as unknown as typeof fetch })
            let settled = false
            const pending = rejection(verifier.verifyAccessToken(minted)).finally(() => (settled = true))
            await until(() => vi.getTimerCount() === 1)
            await vi.advanceTimersByTimeAsync(4999)
            expect(settled).toBe(false)
            await vi.advanceTimersByTimeAsync(1)
            const error = await pending
            expect(error).toBeInstanceOf(BridgeTokenError)
            expect((error as BridgeTokenError).reason).toBe('jwks_unavailable')
        })
    })

    describe('the runtime', () => {
        it('fetches the JWKS with the global fetch when no fetch is given', async () => {
            const real = bridge(keys)
            vi.stubGlobal('fetch', real.fetch)
            const verifier = createVerifier({ issuer: ISSUER, audience: 'acme', fetch: undefined })
            const token = await real.accessToken()
            expect(await verifier.verifyAccessToken(token)).toMatchObject({ userId: decodeJwt(token).sub })
            expect(real.fetched).toEqual([JWKS_URL])
        })

        it('rethrows unchanged an error a runtime missing a Web API raises before any key is loaded', async () => {
            const { real, verifier } = setup()
            const token = await real.accessToken()
            const defect = new TypeError('AbortSignal.timeout is not a function')
            vi.spyOn(AbortSignal, 'timeout').mockImplementation(() => {
                throw defect
            })
            expect(await rejection(verifier.verifyAccessToken(token))).toBe(defect)
            expect(real.fetched).toEqual([])
        })
    })

    describe('BridgeTokenError', () => {
        it('has no cause and quotes neither the token nor its claims', async () => {
            const { real, verifier } = setup()
            const token = await real.accessToken()
            vi.setSystemTime(EXP_MS + 3_600_000)
            const error = await rejection(verifier.verifyAccessToken(token))
            expect(error).toBeInstanceOf(BridgeTokenError)
            expect(error).toBeInstanceOf(Error)
            expect(error).toMatchObject({ name: 'BridgeTokenError', reason: 'expired' })
            expect(error).not.toHaveProperty('cause')
            expect(error).not.toHaveProperty('payload')
            const shown = [String(error), (error as Error).stack ?? '', JSON.stringify(error), JSON.stringify(Object.getOwnPropertyDescriptors(error))].join('\n')
            for (const value of [token, ADA.email, ADA.phoneNumber, ADA.name, decodeJwt(token).sub as string]) expect(shown).not.toContain(value)
        })
    })
})

describe('verifyRequest', () => {
    function request(authorization?: string): Request {
        return new Request('https://api.acme.example/me', authorization === undefined ? {} : { headers: { authorization } })
    }

    it('verifies the bearer token of the Authorization header', async () => {
        const { real, verifier } = setup()
        const token = await real.accessToken()
        expect(await verifier.verifyRequest(request(`Bearer ${token}`))).toMatchObject({ userId: decodeJwt(token).sub, email: ADA.email })
    })

    it('reads the scheme case-insensitively', async () => {
        const { real, verifier } = setup()
        const token = await real.accessToken()
        expect(await verifier.verifyRequest(request(`bearer ${token}`))).toMatchObject({ userId: decodeJwt(token).sub })
    })

    it.each([
        ['no Authorization header', undefined],
        ['another scheme', 'Basic YWRhOnNlY3JldA=='],
        ['a bearer without a token', 'Bearer'],
        ['a bearer with an empty token', 'Bearer   '],
        ['a token without a scheme', 'eyJhbGciOiJFUzI1NiJ9.e30.c2ln'],
    ])('rejects %s as missing', async (_, authorization) => {
        const { verifier } = setup()
        expect(await reason(verifier.verifyRequest(request(authorization)))).toBe('missing')
    })

    it('rejects a bearer token that is not a JWT as malformed', async () => {
        const { verifier } = setup()
        expect(await reason(verifier.verifyRequest(request('Bearer not-a-jwt')))).toBe('malformed')
    })
})
