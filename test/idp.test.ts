import { compactVerify, createLocalJWKSet, SignJWT } from 'jose'
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { parseConfig } from '../src/config'
import { resetJwksCache } from '../src/idp/jwks'
import { ExchangeError, verifySubjectToken } from '../src/idp/verify'
import type { Config, LogCode } from '../src/types'
import { casdoorConfig, clerkConfig } from './helpers/config'
import { fakeDeps } from './helpers/deps'
import { fakeFetch, hang, type FetchCall, type Responder } from './helpers/fetch'
import { base64url, casdoorClaims, clerkClaims, NOW_SEC, signToken, unsignedToken } from './helpers/idp'
import { bridgeSigningKeys, ecKeyPair, idpJwks, rsaKeyPair, type IdpKeyPair } from './helpers/keys'

// Cases edit the documents into any shape
type Doc = Record<string, any>

const CLERK_SUB = 'user_2abcDEFghiJKLmnoPQRstuVWXyz'
const CASDOOR_SUB = '0f5a3c1e-7b2d-4c9e-a8f6-1d2e3b4c5a6f'
const CASDOOR_UID = '6f1c9e2a-3b4d-4e5f-8a6b-7c8d9e0f1a2b'
const OVERRIDE = 'b2d6a1c4-5e7f-4a8b-9c0d-1e2f3a4b5c6d'
const STAGING_ISSUER = 'https://clerk.staging.acme.example'
const STAGING_JWKS = 'https://clerk.staging.acme.example/.well-known/jwks.json'

interface Keys {
    clerk: IdpKeyPair
    other: IdpKeyPair
    casdoor: IdpKeyPair
    casdoorSecond: IdpKeyPair
    ec: IdpKeyPair
    short: IdpKeyPair
}

let keys: Keys

beforeAll(async () => {
    const [clerk, other, casdoor, casdoorSecond, ec, short] = await Promise.all([
        rsaKeyPair({ kid: 'ins_2abcDEFghiJKLmnoPQRstuVWXyz' }),
        rsaKeyPair({ kid: 'other' }),
        rsaKeyPair({ kid: 'cert-built-in' }),
        rsaKeyPair({ kid: 'cert-acme' }),
        ecKeyPair({ kid: 'ec' }),
        rsaKeyPair({ kid: 'short', modulusLength: 1024 }),
    ])
    keys = { clerk, other, casdoor, casdoorSecond, ec, short }
})

beforeEach(() => {
    resetJwksCache()
})

afterEach(() => {
    vi.restoreAllMocks()
})

interface Setup {
    config: Config
    calls: FetchCall[]
    advance: (ms: number) => void
    verify: (token: string, product?: string) => ReturnType<typeof verifySubjectToken>
}

function setup(doc: Doc, respond: Responder, options: { ignoreSignal?: boolean } = {}): Setup {
    const config = parseConfig(JSON.stringify(doc))
    const { fetch, calls } = fakeFetch(respond, options)
    const { deps, advance } = fakeDeps({ fetch })
    const verify = (token: string, product = 'acme') => verifySubjectToken(token, config.products[product]!, config, deps)
    return { config, calls, advance, verify }
}

function serve(...pairs: IdpKeyPair[]): Responder {
    return () => Response.json(idpJwks(...pairs))
}

function clerk(edit: (doc: Doc) => void = () => {}, respond: Responder = serve(keys.clerk)): Setup {
    const doc: Doc = clerkConfig()
    edit(doc)
    return setup(doc, respond)
}

function casdoor(edit: (doc: Doc) => void = () => {}, respond: Responder = serve(keys.casdoor)): Setup {
    const doc: Doc = casdoorConfig()
    edit(doc)
    return setup(doc, respond)
}

// The claims of a Casdoor refresh token, which outlives the access token; Casdoor signs it without a kid
function refreshClaims(): Record<string, unknown> {
    return casdoorClaims({ tokenType: 'refresh-token', exp: NOW_SEC + 7 * 24 * 3600 })
}

// Assigning __proto__ would set the prototype, which JSON.stringify drops, instead of adding the member
function setOwn<T extends object>(object: T, key: string, value: unknown): T {
    Object.defineProperty(object, key, { value, enumerable: true, configurable: true, writable: true })
    return object
}

async function rejection(pending: Promise<unknown>): Promise<unknown> {
    return pending.then(
        () => undefined,
        (caught: unknown) => caught,
    )
}

// The members the token endpoint reads, with idp only when the error has it, so that toStrictEqual also checks
// its absence
async function failure(pending: Promise<unknown>): Promise<Record<string, unknown>> {
    const error = await rejection(pending)
    expect(error).toBeInstanceOf(ExchangeError)
    const { error: oauth, code } = error as ExchangeError
    return Object.hasOwn(error as object, 'idp') ? { error: oauth, code, idp: (error as ExchangeError).idp } : { error: oauth, code }
}

const rejected = (code: LogCode, idp = 'clerk-acme') => ({ error: 'invalid_request', code, idp })
const unbound = (code: LogCode) => ({ error: 'invalid_request', code })
const unavailable = (idp = 'clerk-acme') => ({ error: 'temporarily_unavailable', code: 'jwks_unavailable', idp })

describe('verifySubjectToken', () => {
    describe('Clerk session tokens', () => {
        it('accepts a token with azp and no aud', async () => {
            const { verify, config, calls } = clerk()
            const result = await verify(await signToken(keys.clerk, clerkClaims()))
            expect(result).toStrictEqual({
                idp: config.idps['clerk-acme'],
                subject: CLERK_SUB,
                profile: { email: 'ada@acme.example', name: 'Ada Lovelace', picture: 'https://img.clerk.example/ada.png' },
            })
            expect(calls).toHaveLength(1)
        })

        it('accepts a token without azp, as from a native app, when the binding lists no authorizedParties', async () => {
            const { verify } = clerk()
            const result = await verify(await signToken(keys.clerk, clerkClaims({ azp: undefined })))
            expect(result.subject).toBe(CLERK_SUB)
        })

        it('accepts an azp listed in authorizedParties', async () => {
            const { verify } = clerk((doc) => {
                doc.products.acme.idps[0].authorizedParties = ['https://acme.example', 'capacitor://localhost']
            })
            const result = await verify(await signToken(keys.clerk, clerkClaims({ azp: 'capacitor://localhost' })))
            expect(result.subject).toBe(CLERK_SUB)
        })

        it.each([
            ['another origin', { azp: 'https://evil.example' }],
            ['a missing azp', { azp: undefined }],
            ['an azp that is not a string', { azp: ['https://acme.example'] }],
            ['an azp differing in case', { azp: 'https://ACME.example' }],
        ])('rejects %s when the binding lists authorizedParties', async (_, overrides) => {
            const { verify } = clerk((doc) => {
                doc.products.acme.idps[0].authorizedParties = ['https://acme.example']
            })
            expect(await failure(verify(await signToken(keys.clerk, clerkClaims(overrides))))).toStrictEqual(rejected('client_mismatch'))
        })

        it('returns the uid claim as it is, for deriveUserId to check', async () => {
            const { verify } = clerk()
            expect(await verify(await signToken(keys.clerk, clerkClaims({ uid: OVERRIDE })))).toHaveProperty('uid', OVERRIDE)
            expect(await verify(await signToken(keys.clerk, clerkClaims({ uid: null })))).toHaveProperty('uid', null)
            expect(await verify(await signToken(keys.clerk, clerkClaims({ uid: 'not-a-uuid' })))).toHaveProperty('uid', 'not-a-uuid')
        })

        it('returns no uid when the token has no uid claim', async () => {
            const { verify } = clerk()
            expect(await verify(await signToken(keys.clerk, clerkClaims()))).not.toHaveProperty('uid')
        })

        it('builds the profile through cleanProfile', async () => {
            const { verify } = clerk()
            const claims = clerkClaims({ name: '  Ada Lovelace  ', picture: 'http://img.clerk.example/ada.png', email: 'not an email' })
            expect((await verify(await signToken(keys.clerk, claims))).profile).toStrictEqual({ name: 'Ada Lovelace' })
        })

        it('keeps a phone number only when its default verified claim is true', async () => {
            const { verify } = clerk()
            const phone = { phone_number: '+14155550123', phone_number_verified: true }
            expect((await verify(await signToken(keys.clerk, clerkClaims(phone)))).profile).toHaveProperty('phoneNumber', '+14155550123')
            const unverified = clerkClaims({ ...phone, phone_number_verified: 'true' })
            expect((await verify(await signToken(keys.clerk, unverified))).profile).not.toHaveProperty('phoneNumber')
        })

        it('accepts an ES256 token when the IdP allows ES256', async () => {
            const { verify } = clerk(
                (doc) => {
                    doc.idps['clerk-acme'].algorithms = ['RS256', 'ES256']
                },
                serve(keys.clerk, keys.ec),
            )
            expect((await verify(await signToken(keys.ec, clerkClaims()))).subject).toBe(CLERK_SUB)
        })
    })

    describe('Casdoor JWT-Custom tokens', () => {
        it('accepts an access token with an aud array, emailVerified and a top-level uid', async () => {
            const { verify, config } = casdoor()
            const result = await verify(await signToken(keys.casdoor, casdoorClaims()))
            expect(result).toStrictEqual({
                idp: config.idps.casdoor,
                subject: CASDOOR_SUB,
                uid: CASDOOR_UID,
                profile: { email: 'ada@acme.example', name: 'Ada Lovelace', picture: 'https://cdn.casdoor.example/avatar/ada.png' },
            })
        })

        it('accepts any of the product client ids', async () => {
            const { verify } = casdoor()
            const claims = casdoorClaims({ aud: ['acme-mini-program-client'], azp: 'acme-mini-program-client' })
            expect((await verify(await signToken(keys.casdoor, claims))).subject).toBe(CASDOOR_SUB)
        })

        it('leaves out an email whose emailVerified is not true', async () => {
            const { verify } = casdoor()
            const result = await verify(await signToken(keys.casdoor, casdoorClaims({ emailVerified: false })))
            expect(result.profile).toStrictEqual({ name: 'Ada Lovelace', picture: 'https://cdn.casdoor.example/avatar/ada.png' })
        })

        it('rejects the token of another product on the same instance', async () => {
            const { verify } = casdoor()
            const globex = await signToken(keys.casdoor, casdoorClaims({ aud: ['globex-web-client'], azp: 'globex-web-client' }))
            expect(await failure(verify(globex))).toStrictEqual(rejected('client_mismatch', 'casdoor'))
            expect(await failure(verify(await signToken(keys.casdoor, casdoorClaims()), 'globex'))).toStrictEqual(
                rejected('client_mismatch', 'casdoor'),
            )
        })

        it.each([
            ['an RFC 8707 resource', { aud: ['https://api.acme.example'] }],
            ['a shared application id', { aud: ['acme-web-client-org-acme'] }],
            ['no aud', { aud: undefined }],
            ['an empty aud', { aud: [] }],
        ])('rejects an aud holding %s', async (_, overrides) => {
            const { verify } = casdoor()
            expect(await failure(verify(await signToken(keys.casdoor, casdoorClaims(overrides))))).toStrictEqual(
                rejected('client_mismatch', 'casdoor'),
            )
        })

        describe('with a binding that lists both clientIds and authorizedParties', () => {
            const bothLists = (doc: Doc) => {
                doc.products.acme.idps[0].authorizedParties = ['acme-web-client']
            }

            it('accepts a token whose aud and azp both match', async () => {
                const { verify } = casdoor(bothLists)
                expect((await verify(await signToken(keys.casdoor, casdoorClaims()))).subject).toBe(CASDOOR_SUB)
            })

            it.each([
                ['aud matches but azp does not', { aud: ['acme-web-client'], azp: 'acme-app-client' }],
                ['azp matches but aud does not', { aud: ['https://api.acme.example'], azp: 'acme-web-client' }],
            ])('rejects a token whose %s', async (_, overrides) => {
                const { verify } = casdoor(bothLists)
                expect(await failure(verify(await signToken(keys.casdoor, casdoorClaims(overrides))))).toStrictEqual(
                    rejected('client_mismatch', 'casdoor'),
                )
            })
        })

        it('rejects an ID token by its tokenType', async () => {
            const { verify } = casdoor()
            const idToken = casdoorClaims({ tokenType: 'id-token', jti: 'admin/1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d' })
            expect(await failure(verify(await signToken(keys.casdoor, idToken)))).toStrictEqual(rejected('claim_mismatch', 'casdoor'))
        })

        it('rejects a refresh token by its tokenType when one key is published', async () => {
            const { verify } = casdoor()
            const refresh = await signToken(keys.casdoor, refreshClaims(), { kid: undefined })
            expect(await failure(verify(refresh))).toStrictEqual(rejected('claim_mismatch', 'casdoor'))
        })

        it('rejects a refresh token without kid as unknown_key when two keys are published', async () => {
            const { verify, calls } = casdoor(undefined, serve(keys.casdoor, keys.casdoorSecond))
            const refresh = await signToken(keys.casdoor, refreshClaims(), { kid: undefined })
            expect(await failure(verify(refresh))).toStrictEqual(rejected('unknown_key', 'casdoor'))
            expect(calls).toHaveLength(1)
        })

        it.each([
            ['no tokenType', { tokenType: undefined }],
            ['a tokenType differing in case', { tokenType: 'Access-Token' }],
            ['a tokenType that is not a string', { tokenType: ['access-token'] }],
        ])('rejects %s', async (_, overrides) => {
            const { verify } = casdoor()
            expect(await failure(verify(await signToken(keys.casdoor, casdoorClaims(overrides))))).toStrictEqual(
                rejected('claim_mismatch', 'casdoor'),
            )
        })

        it.each([
            ['a string for a boolean', true, 'true'],
            ['a number for a boolean', true, 1],
            ['a string for a number', 2, '2'],
        ])('compares required claims exactly, so %s differs', async (_, required, actual) => {
            const { verify } = casdoor((doc) => {
                doc.idps.casdoor.requiredClaims.v = required
            })
            expect(await failure(verify(await signToken(keys.casdoor, casdoorClaims({ v: actual }))))).toStrictEqual(
                rejected('claim_mismatch', 'casdoor'),
            )
        })

        it('accepts every required claim of each type when equal', async () => {
            const { verify } = casdoor((doc) => {
                Object.assign(doc.idps.casdoor.requiredClaims, { emailVerified: true, version: 2 })
            })
            expect((await verify(await signToken(keys.casdoor, casdoorClaims({ version: 2 })))).subject).toBe(CASDOOR_SUB)
        })
    })

    describe('before the binding is found', () => {
        const PAYLOAD = base64url(JSON.stringify({ iss: 'https://clerk.acme.example', sub: CLERK_SUB }))

        it.each([
            ['an empty string', ''],
            ['one segment', 'not-a-jwt'],
            ['two segments', `eyJhbGciOiJSUzI1NiJ9.${PAYLOAD}`],
            ['five segments, as a JWE has', `eyJhbGciOiJSU0EtT0FFUCJ9.a.b.c.d`],
            ['an empty payload', 'eyJhbGciOiJSUzI1NiJ9..c2ln'],
            ['a payload that is not base64url', 'eyJhbGciOiJSUzI1NiJ9.!!!.c2ln'],
            ['a payload that is not JSON', `eyJhbGciOiJSUzI1NiJ9.${base64url('{"iss": ')}.c2ln`],
            ['a payload that is an array', `eyJhbGciOiJSUzI1NiJ9.${base64url('["https://clerk.acme.example"]')}.c2ln`],
        ])('rejects %s as malformed_token, with no idp and no fetch', async (_, token) => {
            const { verify, calls } = clerk()
            expect(await failure(verify(token))).toStrictEqual(unbound('malformed_token'))
            expect(calls).toHaveLength(0)
        })

        it.each([
            ['no iss', { iss: undefined }],
            ['a numeric iss', { iss: 42 }],
            ['an iss array', { iss: ['https://clerk.acme.example'] }],
            ['a null iss', { iss: null }],
        ])('rejects %s as malformed_token, with no idp and no fetch', async (_, overrides) => {
            const { verify, calls } = clerk()
            expect(await failure(verify(await signToken(keys.clerk, clerkClaims(overrides))))).toStrictEqual(unbound('malformed_token'))
            expect(calls).toHaveLength(0)
        })

        it.each([
            ['an unknown issuer', 'https://evil.example'],
            ['the issuer with a trailing slash', 'https://clerk.acme.example/'],
            ['the issuer in another case', 'https://CLERK.acme.example'],
            ['the issuer over http', 'http://clerk.acme.example'],
            ['the issuer of an IdP only another product binds', 'https://other.example'],
            ['the bridge itself', 'https://id.acme.example'],
        ])('rejects %s as untrusted_issuer, with no idp and no fetch', async (_, iss) => {
            const { verify, calls } = clerk((doc) => {
                doc.idps.other = { issuer: 'https://other.example', jwksUri: 'https://other.example/jwks' }
                doc.products.globex = { idps: [{ idp: 'other' }] }
            })
            expect(await failure(verify(await signToken(keys.clerk, clerkClaims({ iss }))))).toStrictEqual(unbound('untrusted_issuer'))
            expect(calls).toHaveLength(0)
        })

        it('selects the binding whose IdP issuer equals iss when a product binds several', async () => {
            const { verify, calls } = clerk(
                (doc) => {
                    doc.idps['clerk-staging'] = { issuer: STAGING_ISSUER, jwksUri: STAGING_JWKS, algorithms: ['RS256'] }
                    doc.products.acme.idps.push({ idp: 'clerk-staging' })
                },
                (call) => Response.json(call.url === STAGING_JWKS ? idpJwks(keys.other) : idpJwks(keys.clerk)),
            )
            const result = await verify(await signToken(keys.other, clerkClaims({ iss: STAGING_ISSUER })))
            expect(result.idp.id).toBe('clerk-staging')
            expect(calls.map((call) => call.url)).toEqual([STAGING_JWKS])
            expect(await failure(verify(await signToken(keys.clerk, clerkClaims({ iss: STAGING_ISSUER }))))).toStrictEqual(
                rejected('unknown_key', 'clerk-staging'),
            )
        })
    })

    describe('header and signature', () => {
        // Rows are built before beforeAll generates the keys, so each names its key through a function
        it.each([
            ['ES256', () => keys.ec, {}],
            ['RS512', () => keys.clerk, { alg: 'RS512' }],
            ['PS256', () => keys.clerk, { alg: 'PS256' }],
            ['EdDSA', () => keys.clerk, { alg: 'EdDSA' }],
        ] as const)('rejects %s outside the allowlist as bad_algorithm, with no fetch', async (_, pair, header) => {
            const { verify, calls } = clerk()
            expect(await failure(verify(await signToken(pair(), clerkClaims(), header)))).toStrictEqual(rejected('bad_algorithm'))
            expect(calls).toHaveLength(0)
        })

        it('rejects HS256 as bad_algorithm, with no fetch', async () => {
            const { verify, calls } = clerk()
            const token = await new SignJWT(clerkClaims())
                .setProtectedHeader({ alg: 'HS256', kid: keys.clerk.kid })
                .sign(new TextEncoder().encode('a shared secret of thirty-two by'))
            expect(await failure(verify(token))).toStrictEqual(rejected('bad_algorithm'))
            expect(calls).toHaveLength(0)
        })

        it.each(['none', 'None', 'NONE'])('rejects alg %s as bad_algorithm, with no fetch', async (alg) => {
            const { verify, calls } = clerk()
            expect(await failure(verify(unsignedToken({ alg, typ: 'JWT' }, clerkClaims())))).toStrictEqual(rejected('bad_algorithm'))
            expect(calls).toHaveLength(0)
        })

        it.each([
            ['a header without alg', () => unsignedToken({ typ: 'JWT', kid: 'ins_2abcDEFghiJKLmnoPQRstuVWXyz' }, clerkClaims(), 'c2ln')],
            ['an empty alg', () => unsignedToken({ alg: '' }, clerkClaims(), 'c2ln')],
            ['a header that is not JSON', () => `${base64url('{"alg"')}.${base64url(JSON.stringify(clerkClaims()))}.c2ln`],
            ['a header that is an array', () => `${base64url('["RS256"]')}.${base64url(JSON.stringify(clerkClaims()))}.c2ln`],
        ])('rejects %s as malformed_token, with no fetch', async (_, token) => {
            const { verify, calls } = clerk()
            expect(await failure(verify(token()))).toStrictEqual(rejected('malformed_token'))
            expect(calls).toHaveLength(0)
        })

        it('rejects an unsupported crit extension as malformed_token, with no fetch', async () => {
            const { verify, calls } = clerk()
            const token = await signToken(keys.clerk, clerkClaims(), { crit: ['urn:example:binding'], 'urn:example:binding': true })
            expect(await failure(verify(token))).toStrictEqual(rejected('malformed_token'))
            expect(calls).toHaveLength(0)
        })

        // With b64 false the payload segment is signed as it stands, so the token still decodes and its signature
        // verifies; only jwtVerify's refusal of unencoded payloads stops it
        it('rejects a correctly signed token with an unencoded payload as malformed_token', async () => {
            const { verify, calls } = clerk()
            const token = await signToken(keys.clerk, clerkClaims(), { crit: ['b64'], b64: false })
            await expect(compactVerify(token, createLocalJWKSet(idpJwks(keys.clerk)))).resolves.toHaveProperty('protectedHeader.b64', false)
            expect(await failure(verify(token))).toStrictEqual(rejected('malformed_token'))
            expect(calls).toHaveLength(1)
        })

        it('rejects a signature that is not base64url as malformed_token', async () => {
            const { verify } = clerk()
            const [header, payload] = (await signToken(keys.clerk, clerkClaims())).split('.')
            expect(await failure(verify(`${header}.${payload}.not*base64url`))).toStrictEqual(rejected('malformed_token'))
        })

        it('rejects a token signed by another key under a published kid as bad_signature', async () => {
            const { verify } = clerk()
            const token = await signToken(keys.other, clerkClaims(), { kid: keys.clerk.kid })
            expect(await failure(verify(token))).toStrictEqual(rejected('bad_signature'))
        })

        it('rejects a token whose claims changed after signing as bad_signature', async () => {
            const { verify } = clerk()
            const [header, , signature] = (await signToken(keys.clerk, clerkClaims())).split('.')
            const changed = base64url(JSON.stringify(clerkClaims({ sub: 'user_admin' })))
            expect(await failure(verify(`${header}.${changed}.${signature}`))).toStrictEqual(rejected('bad_signature'))
        })

        it('rejects a truncated signature as bad_signature', async () => {
            const { verify } = clerk()
            const [header, payload] = (await signToken(keys.clerk, clerkClaims())).split('.')
            expect(await failure(verify(`${header}.${payload}.AAAA`))).toStrictEqual(rejected('bad_signature'))
        })

        it('rejects a kid the JWKS does not publish as unknown_key, after one fetch', async () => {
            const { verify, calls } = clerk()
            const token = await signToken(keys.clerk, clerkClaims(), { kid: 'ins_retired' })
            expect(await failure(verify(token))).toStrictEqual(rejected('unknown_key'))
            expect(calls).toHaveLength(1)
        })

        it('rejects a token when the JWKS has no key of its type as unknown_key', async () => {
            const { verify } = clerk(undefined, serve(keys.ec))
            expect(await failure(verify(await signToken(keys.clerk, clerkClaims(), { kid: undefined })))).toStrictEqual(rejected('unknown_key'))
        })
    })

    describe('time and subject claims', () => {
        // Clerk's IdP record allows 60 s of clock skew and tokens up to 900 s old
        it.each([
            ['exp at the edge of the tolerance', { exp: NOW_SEC - 60 }, 'expired'],
            ['exp long past', { exp: NOW_SEC - 3600 }, 'expired'],
            ['iat older than maxTokenAgeSeconds and the tolerance', { iat: NOW_SEC - 961 }, 'too_old'],
            ['iat in the future beyond the tolerance', { iat: NOW_SEC + 61, nbf: undefined }, 'not_yet_valid'],
            ['nbf in the future beyond the tolerance', { nbf: NOW_SEC + 61 }, 'not_yet_valid'],
            ['no iat', { iat: undefined }, 'missing_claim'],
            ['no exp', { exp: undefined }, 'missing_claim'],
            ['no sub', { sub: undefined }, 'missing_claim'],
            ['an empty sub', { sub: '' }, 'missing_claim'],
            ['a numeric sub', { sub: 12345 }, 'missing_claim'],
            ['a null sub', { sub: null }, 'missing_claim'],
            ['an nbf that is not a number', { nbf: 'now' }, 'malformed_token'],
            ['an exp that is not a number', { exp: String(NOW_SEC + 50) }, 'malformed_token'],
            ['an iat that is not a number', { iat: null }, 'malformed_token'],
        ] satisfies [string, Record<string, unknown>, LogCode][])('rejects %s', async (_, overrides, code) => {
            const { verify } = clerk()
            expect(await failure(verify(await signToken(keys.clerk, clerkClaims(overrides))))).toStrictEqual(rejected(code))
        })

        it.each([
            ['exp just inside the tolerance', { exp: NOW_SEC - 59 }],
            ['iat exactly maxTokenAgeSeconds and the tolerance ago', { iat: NOW_SEC - 960 }],
            ['iat in the future within the tolerance', { iat: NOW_SEC + 60, nbf: undefined }],
            ['nbf in the future within the tolerance', { nbf: NOW_SEC + 60 }],
            ['no nbf', { nbf: undefined }],
        ])('accepts %s', async (_, overrides) => {
            const { verify } = clerk()
            expect((await verify(await signToken(keys.clerk, clerkClaims(overrides)))).subject).toBe(CLERK_SUB)
        })

        it('reads the time from deps', async () => {
            const { verify, advance } = clerk()
            const token = await signToken(keys.clerk, clerkClaims())
            expect((await verify(token)).subject).toBe(CLERK_SUB)
            advance(110_000)
            expect(await failure(verify(token))).toStrictEqual(rejected('expired'))
        })
    })

    describe('IdP JWKS', () => {
        it.each([
            ['a 500', () => new Response('internal error', { status: 500 })],
            ['a 404', () => new Response('not found', { status: 404 })],
            ['a redirect', () => new Response(null, { status: 302, headers: { location: 'https://evil.example/jwks' } })],
            ['a 200 HTML page', () => new Response('<!doctype html><title>Sign in</title>', { headers: { 'content-type': 'text/html' } })],
            ['a 200 JSON array', () => Response.json([])],
            ['a network error', () => Promise.reject(new TypeError('Network connection lost.'))],
            ['a JSON object without keys', () => Response.json({ jwks: [] })],
            ['keys that are not objects', () => Response.json({ keys: ['ins_2abcDEFghiJKLmnoPQRstuVWXyz'] })],
        ] satisfies [string, Responder][])('answers jwks_unavailable for %s', async (_, respond) => {
            const { verify, calls } = clerk(undefined, respond)
            expect(await failure(verify(await signToken(keys.clerk, clerkClaims())))).toStrictEqual(unavailable())
            expect(calls).toHaveLength(1)
        })

        it('answers jwks_unavailable for an RSA key under 2048 bits', async () => {
            const { verify } = clerk(undefined, serve(keys.short))
            expect(await failure(verify(await signToken(keys.short, clerkClaims())))).toStrictEqual(unavailable())
        })

        it.each([
            ['a modulus that is not base64url', { n: '!!!' }],
            ['a modulus one byte long', { n: 'AQ' }],
            ['key_ops a public key cannot have', { key_ops: ['sign', 'verify'] }],
        ])('answers jwks_unavailable for a key with %s', async (_, member) => {
            const { verify } = clerk(undefined, () => Response.json({ keys: [{ ...keys.clerk.publicJwk, ...member }] }))
            expect(await failure(verify(await signToken(keys.clerk, clerkClaims())))).toStrictEqual(unavailable())
        })

        it('answers jwks_unavailable for a JWKS that publishes a private key', async () => {
            const { active } = await bridgeSigningKeys()
            const { verify } = clerk(
                (doc) => {
                    doc.idps['clerk-acme'].algorithms = ['ES256']
                },
                () => Response.json({ keys: [{ ...active, kid: keys.ec.kid, alg: 'ES256', use: 'sig' }] }),
            )
            expect(await failure(verify(await signToken(keys.ec, clerkClaims())))).toStrictEqual(unavailable())
        })

        it('answers jwks_unavailable when the timeout signal jose passes aborts', async () => {
            vi.spyOn(AbortSignal, 'timeout').mockImplementation(() => AbortSignal.abort(new DOMException('The operation timed out.', 'TimeoutError')))
            const { verify, calls } = clerk(undefined, hang)
            expect(await failure(verify(await signToken(keys.clerk, clerkClaims())))).toStrictEqual(unavailable())
            expect(calls).toHaveLength(1)
        })

        it('fetches again on the next exchange after a failed fetch', async () => {
            let status = 500
            const { verify, calls } = clerk(undefined, () => (status === 200 ? Response.json(idpJwks(keys.clerk)) : new Response(null, { status })))
            const token = await signToken(keys.clerk, clerkClaims())
            expect(await failure(verify(token))).toStrictEqual(unavailable())
            status = 200
            expect((await verify(token)).subject).toBe(CLERK_SUB)
            expect(calls).toHaveLength(2)
        })

        describe('timeouts', () => {
            // Captured before the timers are faked, to wait in real time for the fetch to start
            const realSetTimeout = globalThis.setTimeout

            beforeEach(() => {
                vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
            })

            afterEach(() => {
                vi.useRealTimers()
            })

            async function fetched(calls: FetchCall[]): Promise<void> {
                for (let tries = 0; calls.length === 0 && tries < 200; tries++) await new Promise((resolve) => realSetTimeout(resolve, 5))
                expect(calls).toHaveLength(1)
            }

            it.each([
                ['the IdP never answers', false],
                ['the fetch ignores its signal, so only the bridge timer can end it', true],
            ])('answers jwks_unavailable after 5 s when %s', async (_, ignoreSignal) => {
                const { verify, calls } = setup(clerkConfig(), hang, { ignoreSignal })
                const pending = failure(verify(await signToken(keys.clerk, clerkClaims())))
                await fetched(calls)
                await vi.advanceTimersByTimeAsync(5000)
                expect(await pending).toStrictEqual(unavailable())
            })
        })
    })

    describe('key sets', () => {
        it('fetches the JWKS once for consecutive exchanges', async () => {
            const { verify, calls } = clerk()
            await verify(await signToken(keys.clerk, clerkClaims()))
            await verify(await signToken(keys.clerk, clerkClaims({ sub: 'user_other' })))
            expect(calls).toHaveLength(1)
        })

        it('picks up a rotated key after an unknown kid when the cooldown has passed', async () => {
            resetJwksCache({ cooldownDuration: 0 })
            let published = keys.clerk
            const { verify, calls } = clerk(undefined, () => Response.json(idpJwks(published)))
            expect((await verify(await signToken(keys.clerk, clerkClaims()))).subject).toBe(CLERK_SUB)
            published = keys.other
            expect((await verify(await signToken(keys.other, clerkClaims()))).subject).toBe(CLERK_SUB)
            expect(calls).toHaveLength(2)
            expect(await failure(verify(await signToken(keys.clerk, clerkClaims())))).toStrictEqual(rejected('unknown_key'))
        })

        it('fetches no more than once per exchange within the default cooldown', async () => {
            let published = keys.clerk
            const { verify, calls } = clerk(undefined, () => Response.json(idpJwks(published)))
            await verify(await signToken(keys.clerk, clerkClaims()))
            published = keys.other
            expect(await failure(verify(await signToken(keys.other, clerkClaims())))).toStrictEqual(rejected('unknown_key'))
            expect(calls).toHaveLength(1)
        })
    })

    describe('order of checks', () => {
        const idToken = () => casdoorClaims({ tokenType: 'id-token' })

        it('checks the algorithm before looking for the key', async () => {
            const { verify, calls } = casdoor()
            expect(await failure(verify(unsignedToken({ alg: 'none', kid: 'ins_unknown' }, idToken())))).toStrictEqual(
                rejected('bad_algorithm', 'casdoor'),
            )
            expect(calls).toHaveLength(0)
        })

        it('checks the signature before any claim', async () => {
            const { verify } = casdoor()
            const forged = await signToken(keys.other, casdoorClaims({ tokenType: 'id-token', exp: NOW_SEC - 3600 }), { kid: keys.casdoor.kid })
            expect(await failure(verify(forged))).toStrictEqual(rejected('bad_signature', 'casdoor'))
        })

        it('checks the time claims before the required claims', async () => {
            const { verify } = casdoor()
            const expired = await signToken(keys.casdoor, casdoorClaims({ tokenType: 'id-token', exp: NOW_SEC - 3600 }))
            expect(await failure(verify(expired))).toStrictEqual(rejected('expired', 'casdoor'))
        })

        it('checks the required claims before the client binding', async () => {
            const { verify } = casdoor()
            const globexIdToken = await signToken(keys.casdoor, { ...idToken(), aud: ['globex-web-client'], azp: 'globex-web-client' })
            expect(await failure(verify(globexIdToken))).toStrictEqual(rejected('claim_mismatch', 'casdoor'))
        })

        it('checks the client binding before the subject', async () => {
            const { verify } = casdoor()
            const globex = await signToken(keys.casdoor, casdoorClaims({ aud: ['globex-web-client'], sub: '' }))
            expect(await failure(verify(globex))).toStrictEqual(rejected('client_mismatch', 'casdoor'))
        })
    })

    describe('prototype member names', () => {
        it('reads a required claim named __proto__ only from the token itself', async () => {
            const { verify } = casdoor((doc) => {
                doc.idps.casdoor.requiredClaims = setOwn({}, '__proto__', 'access-token')
            })
            const own = setOwn(casdoorClaims(), '__proto__', 'access-token')
            expect((await verify(await signToken(keys.casdoor, own))).subject).toBe(CASDOOR_SUB)
            expect(await failure(verify(await signToken(keys.casdoor, casdoorClaims())))).toStrictEqual(rejected('claim_mismatch', 'casdoor'))
        })

        it('reads a required claim named constructor only from the token itself', async () => {
            const { verify } = casdoor((doc) => {
                doc.idps.casdoor.requiredClaims = { constructor: 'access-token' }
            })
            expect((await verify(await signToken(keys.casdoor, casdoorClaims({ constructor: 'access-token' })))).subject).toBe(CASDOOR_SUB)
            expect(await failure(verify(await signToken(keys.casdoor, casdoorClaims())))).toStrictEqual(rejected('claim_mismatch', 'casdoor'))
        })

        it('reads a uid claim named constructor only from the token itself', async () => {
            const { verify } = clerk((doc) => {
                doc.idps['clerk-acme'].claims.uid = 'constructor'
            })
            expect(await verify(await signToken(keys.clerk, clerkClaims()))).not.toHaveProperty('uid')
            expect(await verify(await signToken(keys.clerk, clerkClaims({ constructor: OVERRIDE })))).toHaveProperty('uid', OVERRIDE)
        })

        it('reads client ids from a claim named __proto__ only from the token itself', async () => {
            const { verify } = casdoor((doc) => {
                doc.idps.casdoor.claims.clientId = '__proto__'
            })
            const own = setOwn(casdoorClaims(), '__proto__', 'acme-web-client')
            expect((await verify(await signToken(keys.casdoor, own))).subject).toBe(CASDOOR_SUB)
            expect(await failure(verify(await signToken(keys.casdoor, casdoorClaims())))).toStrictEqual(rejected('client_mismatch', 'casdoor'))
        })
    })

    describe('unexpected errors', () => {
        it('rethrows a TypeError raised before any JWKS was fetched', async () => {
            const problem = new TypeError('AbortSignal.timeout is not a function')
            vi.spyOn(AbortSignal, 'timeout').mockImplementation(() => {
                throw problem
            })
            const { verify, calls } = clerk()
            expect(await rejection(verify(await signToken(keys.clerk, clerkClaims())))).toBe(problem)
            expect(calls).toHaveLength(0)
        })

        it.each([NaN, Infinity, -Infinity])('throws a plain error, before any fetch, when the clock reads %s', async (reading) => {
            const config = parseConfig(JSON.stringify(clerkConfig()))
            const { fetch, calls } = fakeFetch(serve(keys.clerk))
            const { deps } = fakeDeps({ fetch, now: () => reading })
            const token = await signToken(keys.clerk, clerkClaims())
            const error = await rejection(verifySubjectToken(token, config.products.acme!, config, deps))
            expect(error).toBeInstanceOf(Error)
            expect(error).not.toBeInstanceOf(ExchangeError)
            expect(calls).toHaveLength(0)
        })

        it('rethrows an error it does not map', async () => {
            const problem = new Error('unexpected')
            vi.spyOn(crypto.subtle, 'importKey').mockRejectedValue(problem)
            const { verify } = clerk()
            expect(await rejection(verify(await signToken(keys.clerk, clerkClaims())))).toBe(problem)
        })
    })

    describe('ExchangeError', () => {
        it('has the log code as its message and never quotes the token', async () => {
            const { verify } = clerk()
            const token = await signToken(keys.other, clerkClaims(), { kid: keys.clerk.kid })
            const error = await rejection(verify(token))
            expect(error).toBeInstanceOf(ExchangeError)
            expect(error).toBeInstanceOf(Error)
            expect((error as ExchangeError).name).toBe('ExchangeError')
            expect((error as ExchangeError).message).toBe('bad_signature')
            expect(JSON.stringify(error, Object.getOwnPropertyNames(error))).not.toContain(token.split('.')[1])
        })

        it('carries the IdP id only once the binding is found', async () => {
            const { verify } = clerk()
            const malformed = await rejection(verify('not-a-jwt'))
            const untrusted = await rejection(verify(await signToken(keys.clerk, clerkClaims({ iss: 'https://evil.example' }))))
            const expired = await rejection(verify(await signToken(keys.clerk, clerkClaims({ exp: NOW_SEC - 3600 }))))
            expect('idp' in (malformed as object)).toBe(false)
            expect('idp' in (untrusted as object)).toBe(false)
            expect((expired as ExchangeError).idp).toBe('clerk-acme')
        })
    })
})
