import { createLocalJWKSet, decodeJwt, jwtVerify, type JSONWebKeySet } from 'jose'
import { beforeAll, describe, expect, it } from 'vitest'
import { handle } from '../src/app'
import { parseConfig } from '../src/config'
import { importSigningKeys } from '../src/keys'
import type { Deps, LogCode, LogLine, OAuthErrorCode, Runtime, SigningKeys } from '../src/types'
import { casdoorConfig, clerkConfig } from './helpers/config'
import { fakeDeps, START_MS } from './helpers/deps'
import { fakeFetch, type FetchCall, type Responder } from './helpers/fetch'
import { casdoorClaims, clerkClaims, NOW_SEC, signToken } from './helpers/idp'
import { bridgeSigningKeys, ecKeyPair, idpJwks, rsaKeyPair, type IdpKeyPair } from './helpers/keys'
import golden from './fixtures/golden-ids.json'

// Cases edit the documents into any shape
type Doc = Record<string, any>
type Deployment = 'clerk' | 'casdoor'

const TOKEN_URL = 'https://id.acme.example/token'
const JWKS_URL = 'https://id.acme.example/.well-known/jwks.json'
const FORM = 'application/x-www-form-urlencoded'
const MAX_BODY_BYTES = 16384
const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
const JWT_TYPE = 'urn:ietf:params:oauth:token-type:jwt'
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'
const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token'

// The golden fixture's Clerk user without override
const CLERK_SUBJECT = 'user_2pXk7QmZbLr9TfWc4NvHs8YdJe1'
const CLERK_USER = 'd4b7bc25-004f-5965-a191-6da1608b6639'
const CASDOOR_UID = '6f1c9e2a-3b4d-4e5f-8a6b-7c8d9e0f1a2b'
const FIRST_JTI = '00000000-0000-4000-8000-000000000001'

const MALFORMED = 'The request is malformed.'
const NOT_ACCEPTABLE = 'The subject token is not acceptable.'
const NO_AUDIENCE = 'The requested audience is not available.'
const NO_SCOPES = 'Scopes are not supported.'
const ONLY_EXCHANGE = 'Only token exchange is supported.'
const TOO_LARGE = 'The request is too large.'
const IDP_UNAVAILABLE = 'The identity provider is unavailable.'
const FAILED = 'The service failed.'

interface Keys {
    bridge: SigningKeys
    clerk: IdpKeyPair
    other: IdpKeyPair
    casdoor: IdpKeyPair
    ec: IdpKeyPair
}

let keys: Keys

beforeAll(async () => {
    const [bridge, clerk, other, casdoor, ec] = await Promise.all([
        bridgeSigningKeys(1).then((generated) => importSigningKeys(generated.json)),
        rsaKeyPair({ kid: 'ins_2abcDEFghiJKLmnoPQRstuVWXyz' }),
        rsaKeyPair({ kid: 'other' }),
        rsaKeyPair({ kid: 'cert-built-in' }),
        ecKeyPair({ kid: 'ec' }),
    ])
    keys = { bridge, clerk, other, casdoor, ec }
})

interface Setup {
    logs: LogLine[]
    calls: FetchCall[]
    send: (request: Request) => Promise<Response>
}

interface SetupOptions {
    edit?: (doc: Doc) => void
    respond?: Responder
    deps?: Partial<Deps>
}

function serve(...pairs: IdpKeyPair[]): Responder {
    return () => Response.json(idpJwks(...pairs))
}

// Each call parses its own configuration, so no two tests share the IdP key sets cached per parsed IdP record
function setup(deployment: Deployment = 'clerk', options: SetupOptions = {}): Setup {
    const doc: Doc = deployment === 'clerk' ? clerkConfig() : casdoorConfig()
    options.edit?.(doc)
    const { fetch, calls } = fakeFetch(options.respond ?? serve(deployment === 'clerk' ? keys.clerk : keys.casdoor))
    const { deps, logs } = fakeDeps({ fetch, ...options.deps })
    const runtime: Runtime = {
        config: parseConfig(JSON.stringify(doc)),
        keys: keys.bridge,
        webhookSecret: () => {
            throw new Error('not read by this route')
        },
    }
    return { logs, calls, send: (request) => handle(request, runtime, deps) }
}

function clerkToken(overrides: Record<string, unknown> = {}): Promise<string> {
    return signToken(keys.clerk, clerkClaims(overrides))
}

// Signed by another key under the kid the Clerk JWKS publishes
function forgedClerkToken(overrides: Record<string, unknown> = {}): Promise<string> {
    return signToken(keys.other, clerkClaims(overrides), { kid: keys.clerk.kid })
}

function casdoorToken(overrides: Record<string, unknown> = {}): Promise<string> {
    return signToken(keys.casdoor, casdoorClaims(overrides))
}

type Edit = (params: URLSearchParams) => void

const set =
    (name: string, value: string): Edit =>
    (params) =>
        params.set(name, value)
const add =
    (name: string, value: string): Edit =>
    (params) =>
        params.append(name, value)
const drop =
    (name: string): Edit =>
    (params) =>
        params.delete(name)
const all =
    (...edits: Edit[]): Edit =>
    (params) => {
        for (const edit of edits) edit(params)
    }

// The parameters of a valid exchange for product acme, which each case edits
function form(subjectToken: string, edit: Edit = () => {}): string {
    const params = new URLSearchParams({ grant_type: TOKEN_EXCHANGE, subject_token: subjectToken, subject_token_type: JWT_TYPE, audience: 'acme' })
    edit(params)
    return params.toString()
}

// A null content type sends the body as bytes, for which Request sets no Content-Type of its own
function post(body: string, contentType: string | null = FORM, headers: Record<string, string> = {}): Request {
    if (contentType === null) return new Request(TOKEN_URL, { method: 'POST', headers, body: new TextEncoder().encode(body) })
    return new Request(TOKEN_URL, { method: 'POST', headers: { 'content-type': contentType, ...headers }, body })
}

async function expectIssued(response: Response, expiresIn = 900): Promise<string> {
    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toBe('application/json')
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(response.headers.get('pragma')).toBe('no-cache')
    expect(response.headers.get('vary')).toBe('Origin')
    const body = (await response.json()) as Record<string, unknown>
    expect(body).toStrictEqual({
        access_token: expect.any(String),
        issued_token_type: ACCESS_TOKEN_TYPE,
        token_type: 'Bearer',
        expires_in: expiresIn,
    })
    return body.access_token as string
}

async function expectError(response: Response, status: number, error: OAuthErrorCode, description: string): Promise<void> {
    expect(response.status).toBe(status)
    expect(response.headers.get('content-type')).toBe('application/json')
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(response.headers.get('pragma')).toBe('no-cache')
    expect(response.headers.get('vary')).toBe('Origin')
    expect(await response.json()).toStrictEqual({ error, error_description: description })
}

function line(status: number, code: LogCode, known: { product?: string; idp?: string } = {}): LogLine {
    return { route: 'token', status, ms: 0, outcome: status >= 500 ? 'error' : 'rejected', code, ...known }
}

async function bridgeJwks(send: Setup['send']) {
    return createLocalJWKSet((await (await send(new Request(JWKS_URL))).json()) as JSONWebKeySet)
}

describe('/token', () => {
    describe('a valid exchange', () => {
        it('issues a Clerk user an access token that verifies against the bridge JWKS', async () => {
            const { send, logs } = setup()
            const accessToken = await expectIssued(await send(post(form(await clerkToken({ sub: CLERK_SUBJECT })))))
            const { payload, protectedHeader } = await jwtVerify(accessToken, await bridgeJwks(send), {
                issuer: 'https://id.acme.example',
                audience: 'acme',
                typ: 'at+jwt',
                algorithms: ['ES256'],
                currentDate: new Date(START_MS),
            })
            expect(protectedHeader).toStrictEqual({ alg: 'ES256', typ: 'at+jwt', kid: keys.bridge.kid })
            expect(payload).toStrictEqual({
                iss: 'https://id.acme.example',
                sub: CLERK_USER,
                aud: 'acme',
                client_id: 'acme',
                jti: FIRST_JTI,
                idp: 'clerk-acme',
                region: 'us',
                email: 'ada@acme.example',
                name: 'Ada Lovelace',
                picture: 'https://img.clerk.example/ada.png',
                iat: NOW_SEC,
                exp: NOW_SEC + 900,
            })
            expect(logs).toEqual([
                { route: 'token', status: 200, ms: 0, outcome: 'ok', product: 'acme', idp: 'clerk-acme' },
                { route: 'jwks', status: 200, ms: 0, outcome: 'ok' },
            ])
        })

        it('issues a Casdoor user an access token with its uid override as sub', async () => {
            const { send } = setup('casdoor')
            const accessToken = await expectIssued(await send(post(form(await casdoorToken()))))
            const { payload } = await jwtVerify(accessToken, await bridgeJwks(send), {
                issuer: 'https://id.cn.acme.example',
                audience: 'acme',
                typ: 'at+jwt',
                algorithms: ['ES256'],
                currentDate: new Date(START_MS),
            })
            expect(payload).toStrictEqual({
                iss: 'https://id.cn.acme.example',
                sub: CASDOOR_UID,
                aud: 'acme',
                client_id: 'acme',
                jti: FIRST_JTI,
                idp: 'casdoor',
                region: 'cn',
                email: 'ada@acme.example',
                name: 'Ada Lovelace',
                picture: 'https://cdn.casdoor.example/avatar/ada.png',
                iat: NOW_SEC,
                exp: NOW_SEC + 900,
            })
        })

        it('answers expires_in from tokenTtlSeconds', async () => {
            const { send } = setup('clerk', {
                edit: (doc) => {
                    doc.tokenTtlSeconds = 600
                },
            })
            const claims = decodeJwt(await expectIssued(await send(post(form(await clerkToken()))), 600))
            expect(claims.exp! - claims.iat!).toBe(600)
        })

        it('takes the issue time in whole seconds and the jti from deps', async () => {
            const jti = '9b2f6c1e-4d3a-4e5b-8c7d-6e5f4a3b2c1d'
            const { send } = setup('clerk', { deps: { now: () => START_MS + 1999, randomUUID: () => jti } })
            const claims = decodeJwt(await expectIssued(await send(post(form(await clerkToken())))))
            expect(claims).toMatchObject({ iat: NOW_SEC + 1, exp: NOW_SEC + 901, jti })
        })

        it.each([
            ['subject_token_type access_token', set('subject_token_type', ACCESS_TOKEN_TYPE)],
            ['subject_token_type id_token', set('subject_token_type', ID_TOKEN_TYPE)],
            ['requested_token_type access_token', set('requested_token_type', ACCESS_TOKEN_TYPE)],
            ['an unrecognized parameter', set('client_id', 'acme-web')],
            ['an unrecognized parameter repeated', all(add('nonce', 'a'), add('nonce', 'b'))],
            [
                'empty scope, resource, actor_token, actor_token_type and requested_token_type, as if absent',
                all(...['scope', 'resource', 'actor_token', 'actor_token_type', 'requested_token_type'].map((name) => set(name, ''))),
            ],
            ['a second, empty audience', add('audience', '')],
            ['a second, empty subject_token', add('subject_token', '')],
        ])('accepts a request with %s', async (_, edit) => {
            const { send } = setup()
            await expectIssued(await send(post(form(await clerkToken(), edit))))
        })

        it.each([
            'Application/X-WWW-Form-Urlencoded; charset=utf-8',
            'application/x-www-form-urlencoded;charset=UTF-8',
            'application/x-www-form-urlencoded ; charset=utf-8',
        ])('accepts Content-Type %j', async (contentType) => {
            const { send } = setup()
            await expectIssued(await send(post(form(await clerkToken()), contentType)))
        })

        it('accepts a body of exactly 16 KiB', async () => {
            const { send } = setup()
            const body = `${form(await clerkToken())}&pad=`
            await expectIssued(await send(post(body.padEnd(MAX_BODY_BYTES, 'a'))))
        })
    })

    describe('errors', () => {
        it('answers 400 invalid_request bad_request for a malformed request', async () => {
            const { send, logs } = setup()
            await expectError(await send(post(form(await clerkToken()), 'application/json')), 400, 'invalid_request', MALFORMED)
            expect(logs).toEqual([line(400, 'bad_request')])
        })

        // Rows are built before beforeAll generates the keys, so each signs its token through a function
        it.each([
            ['a token that is not a JWT', 'clerk', 'malformed_token', undefined, async () => 'not-a-jwt'],
            ['an issuer the product does not bind', 'clerk', 'untrusted_issuer', undefined, () => clerkToken({ iss: 'https://evil.example' })],
            ['an algorithm outside the allowlist', 'clerk', 'bad_algorithm', 'clerk-acme', () => signToken(keys.ec, clerkClaims())],
            ['a signature by another key', 'clerk', 'bad_signature', 'clerk-acme', () => forgedClerkToken()],
            ['a kid the JWKS does not publish', 'clerk', 'unknown_key', 'clerk-acme', () => signToken(keys.clerk, clerkClaims(), { kid: 'ins_old' })],
            ['an expired token', 'clerk', 'expired', 'clerk-acme', () => clerkToken({ exp: NOW_SEC - 3600 })],
            ['a token older than maxTokenAgeSeconds', 'clerk', 'too_old', 'clerk-acme', () => clerkToken({ iat: NOW_SEC - 961 })],
            ['a token not valid yet', 'clerk', 'not_yet_valid', 'clerk-acme', () => clerkToken({ nbf: NOW_SEC + 61 })],
            ['a token without sub', 'clerk', 'missing_claim', 'clerk-acme', () => clerkToken({ sub: undefined })],
            ['a required claim that differs', 'casdoor', 'claim_mismatch', 'casdoor', () => casdoorToken({ tokenType: 'id-token' })],
            [
                'the client id of another product',
                'casdoor',
                'client_mismatch',
                'casdoor',
                () => casdoorToken({ aud: ['globex-web-client'], azp: 'globex-web-client' }),
            ],
            ['a malformed uid override', 'clerk', 'bad_uid', 'clerk-acme', () => clerkToken({ uid: 'not-a-uuid' })],
        ] satisfies [string, Deployment, LogCode, string | undefined, () => Promise<string>][])(
            'answers 400 invalid_request for %s, logged as %s',
            async (_, deployment, code, idp, token) => {
                const { send, logs } = setup(deployment)
                await expectError(await send(post(form(await token()))), 400, 'invalid_request', NOT_ACCEPTABLE)
                expect(logs).toEqual([line(400, code, idp === undefined ? { product: 'acme' } : { product: 'acme', idp })])
            },
        )

        it.each([
            ['an unknown audience', 'unknown_product', set('audience', 'globex')],
            ['more than one audience', 'bad_request', add('audience', 'globex')],
            ['a resource', 'bad_request', set('resource', 'https://api.acme.example')],
        ] satisfies [string, LogCode, Edit][])('answers 400 invalid_target for %s', async (_, code, edit) => {
            const { send, logs, calls } = setup()
            await expectError(await send(post(form(await clerkToken(), edit))), 400, 'invalid_target', NO_AUDIENCE)
            expect(logs).toEqual([line(400, code)])
            expect(calls).toHaveLength(0)
        })

        it('answers 400 invalid_scope for a scope', async () => {
            const { send, logs } = setup()
            await expectError(await send(post(form(await clerkToken(), set('scope', 'openid')))), 400, 'invalid_scope', NO_SCOPES)
            expect(logs).toEqual([line(400, 'bad_request')])
        })

        it('answers 400 unsupported_grant_type for another grant type', async () => {
            const { send, logs } = setup()
            const body = form(await clerkToken(), set('grant_type', 'authorization_code'))
            await expectError(await send(post(body)), 400, 'unsupported_grant_type', ONLY_EXCHANGE)
            expect(logs).toEqual([line(400, 'unsupported_grant')])
        })

        it('answers 413 invalid_request for a body over 16 KiB', async () => {
            const { send, logs, calls } = setup()
            const body = `${form(await clerkToken())}&pad=`
            await expectError(await send(post(body.padEnd(MAX_BODY_BYTES + 1, 'a'))), 413, 'invalid_request', TOO_LARGE)
            expect(logs).toEqual([line(413, 'too_large')])
            expect(calls).toHaveLength(0)
        })

        it('answers 413 for a declared Content-Length over 16 KiB', async () => {
            const { send, logs } = setup()
            const request = post(form(await clerkToken()), FORM, { 'content-length': String(MAX_BODY_BYTES + 1) })
            await expectError(await send(request), 413, 'invalid_request', TOO_LARGE)
            expect(logs).toEqual([line(413, 'too_large')])
        })

        it('answers 503 temporarily_unavailable when the IdP JWKS cannot be fetched', async () => {
            const { send, logs } = setup('clerk', { respond: () => new Response('down', { status: 500 }) })
            await expectError(await send(post(form(await clerkToken()))), 503, 'temporarily_unavailable', IDP_UNAVAILABLE)
            expect(logs).toEqual([line(503, 'jwks_unavailable', { product: 'acme', idp: 'clerk-acme' })])
        })

        it('answers 500 server_error in failure mode', async () => {
            const { deps, logs } = fakeDeps()
            const response = await handle(post(form(await clerkToken())), { reason: 'runtime loading failed' }, deps)
            await expectError(response, 500, 'server_error', FAILED)
            expect(logs).toEqual([line(500, 'runtime_unavailable')])
        })

        it('answers 500 server_error for an unexpected error, keeping what was learnt and never echoing the error', async () => {
            const token = await clerkToken()
            const { send, logs } = setup('clerk', {
                deps: {
                    randomUUID: () => {
                        throw new Error(`no randomness for ${token}`)
                    },
                },
            })
            const response = await send(post(form(token)))
            const text = await response.clone().text()
            await expectError(response, 500, 'server_error', FAILED)
            expect(logs).toEqual([line(500, 'internal_error', { product: 'acme', idp: 'clerk-acme' })])
            expect(text + JSON.stringify(logs)).not.toContain(token.split('.')[1])
        })
    })

    describe('request validation', () => {
        it.each([
            ['no Content-Type', null],
            ['application/x-www-form-urlencodedx', 'application/x-www-form-urlencodedx'],
            ['application/json', 'application/json'],
            ['text/plain', 'text/plain;charset=UTF-8'],
            ['multipart/form-data', 'multipart/form-data; boundary=x'],
            ['form with a second type after a comma', 'application/x-www-form-urlencoded, text/plain'],
        ])('rejects %s as bad_request, before reading the body', async (_, contentType) => {
            const { send, logs, calls } = setup()
            const request = post(form(await clerkToken()), contentType)
            await expectError(await send(request), 400, 'invalid_request', MALFORMED)
            expect(request.bodyUsed).toBe(false)
            expect(logs).toEqual([line(400, 'bad_request')])
            expect(calls).toHaveLength(0)
        })

        it.each([
            ['a duplicate subject_token', add('subject_token', 'eyJ.eyJ.c2ln')],
            ['a repeated grant_type', add('grant_type', TOKEN_EXCHANGE)],
            ['a repeated grant_type whose first value is another grant', all(set('grant_type', 'password'), add('grant_type', TOKEN_EXCHANGE))],
            ['a repeated subject_token_type', add('subject_token_type', JWT_TYPE)],
            ['a repeated scope', all(add('scope', 'a'), add('scope', 'b'))],
            ['a repeated resource', all(add('resource', 'a'), add('resource', 'b'))],
            ['a missing grant_type', drop('grant_type')],
            ['an empty grant_type', set('grant_type', '')],
            ['a missing subject_token', drop('subject_token')],
            ['an empty subject_token', set('subject_token', '')],
            ['a missing audience', drop('audience')],
            ['an empty audience', set('audience', '')],
            ['a missing subject_token_type', drop('subject_token_type')],
            ['a subject_token_type of refresh_token', set('subject_token_type', 'urn:ietf:params:oauth:token-type:refresh_token')],
            ['a subject_token_type in another case', set('subject_token_type', JWT_TYPE.toUpperCase())],
            ['a requested_token_type of id_token', set('requested_token_type', ID_TOKEN_TYPE)],
            ['an actor_token', set('actor_token', 'eyJ.eyJ.c2ln')],
            ['an actor_token_type alone', set('actor_token_type', JWT_TYPE)],
        ])('rejects %s as invalid_request bad_request', async (_, edit) => {
            const { send, logs, calls } = setup()
            await expectError(await send(post(form(await clerkToken(), edit))), 400, 'invalid_request', MALFORMED)
            expect(logs).toEqual([line(400, 'bad_request')])
            expect(calls).toHaveLength(0)
        })

        it('rejects two audience values as invalid_target', async () => {
            const { send, logs } = setup()
            const body = form(await clerkToken(), add('audience', 'acme'))
            await expectError(await send(post(body)), 400, 'invalid_target', NO_AUDIENCE)
            expect(logs).toEqual([line(400, 'bad_request')])
        })

        it.each(['constructor', '__proto__', 'toString', 'hasOwnProperty', 'ACME', 'acme '])(
            'rejects audience=%j as invalid_target unknown_product',
            async (audience) => {
                const { send, logs, calls } = setup()
                await expectError(await send(post(form(await clerkToken(), set('audience', audience)))), 400, 'invalid_target', NO_AUDIENCE)
                expect(logs).toEqual([line(400, 'unknown_product')])
                expect(calls).toHaveLength(0)
            },
        )

        it('rejects a grant_type in another case as unsupported_grant_type', async () => {
            const { send } = setup()
            const body = form(await clerkToken(), set('grant_type', TOKEN_EXCHANGE.toUpperCase()))
            await expectError(await send(post(body)), 400, 'unsupported_grant_type', ONLY_EXCHANGE)
        })

        // Each request breaks two rules; the first check in order decides
        it.each([
            ['two audiences before a repeated parameter', 'invalid_target', 'bad_request', all(add('audience', 'globex'), add('subject_token', 'x'))],
            ['a repeat before the grant type', 'invalid_request', 'bad_request', all(set('grant_type', 'password'), add('grant_type', 'x'))],
            ['the grant type before a resource', 'unsupported_grant_type', 'unsupported_grant', all(set('grant_type', 'x'), set('resource', 'x'))],
            ['a missing grant type before a scope', 'invalid_request', 'bad_request', all(drop('grant_type'), set('scope', 'openid'))],
            ['a resource before a scope', 'invalid_target', 'bad_request', all(set('resource', 'x'), set('scope', 'openid'))],
            ['a scope before an actor token', 'invalid_scope', 'bad_request', all(set('scope', 'openid'), set('actor_token', 'x'))],
            ['the request shape before the audience', 'invalid_request', 'bad_request', all(set('audience', 'globex'), set('actor_token', 'x'))],
        ] satisfies [string, OAuthErrorCode, LogCode, Edit][])('checks %s', async (_, error, code, edit) => {
            const { send, logs } = setup()
            const response = await send(post(form(await clerkToken(), edit)))
            expect(response.status).toBe(400)
            expect(await response.json()).toMatchObject({ error })
            expect(logs).toEqual([line(400, code)])
        })

        it('checks the content type before the body size', async () => {
            const { send, logs } = setup()
            await expectError(await send(post('a'.repeat(MAX_BODY_BYTES + 1), 'text/plain')), 400, 'invalid_request', MALFORMED)
            expect(logs).toEqual([line(400, 'bad_request')])
        })

        it('checks the body size before the parameters', async () => {
            const { send, logs } = setup()
            await expectError(await send(post(`scope=a&scope=b&pad=`.padEnd(MAX_BODY_BYTES + 1, 'a'))), 413, 'invalid_request', TOO_LARGE)
            expect(logs).toEqual([line(413, 'too_large')])
        })
    })

    describe('CORS', () => {
        const ACME_ORIGIN = 'https://cn.acme.example'
        const GLOBEX_ORIGIN = 'https://globex.example'
        const CORS_HEADERS = ['access-control-allow-origin', 'access-control-allow-methods', 'access-control-allow-headers', 'access-control-max-age']

        // Two products on one Casdoor instance, each listing an origin of its own
        function cors(deps: Partial<Deps> = {}, respond?: Responder): Setup {
            return setup('casdoor', {
                edit: (doc) => {
                    doc.products.globex.allowedOrigins = [GLOBEX_ORIGIN]
                },
                deps,
                ...(respond === undefined ? {} : { respond }),
            })
        }

        function preflight(origin?: string): Request {
            const headers: Record<string, string> = { 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type' }
            if (origin !== undefined) headers.origin = origin
            return new Request(TOKEN_URL, { method: 'OPTIONS', headers })
        }

        function corsHeaders(response: Response): Record<string, string | null> {
            return Object.fromEntries(CORS_HEADERS.map((name) => [name, response.headers.get(name)]))
        }

        const NONE = Object.fromEntries(CORS_HEADERS.map((name) => [name, null]))
        const allowed = (origin: string) => ({ ...NONE, 'access-control-allow-origin': origin })

        it.each([ACME_ORIGIN, GLOBEX_ORIGIN])('answers a preflight from %s, which a product lists, 204 with CORS headers', async (origin) => {
            const { send, logs, calls } = cors()
            const response = await send(preflight(origin))
            expect(response.status).toBe(204)
            expect(await response.text()).toBe('')
            expect(response.headers.get('vary')).toBe('Origin')
            expect(corsHeaders(response)).toStrictEqual({
                'access-control-allow-origin': origin,
                'access-control-allow-methods': 'POST',
                'access-control-allow-headers': 'Content-Type',
                'access-control-max-age': '600',
            })
            expect(logs).toEqual([{ route: 'token', status: 204, ms: 0, outcome: 'ok' }])
            expect(calls).toHaveLength(0)
        })

        it.each([
            ['an origin no product lists', 'https://evil.example'],
            ['a listed origin in another case', 'https://CN.acme.example'],
            ['a listed origin with a trailing slash', `${ACME_ORIGIN}/`],
            ['the opaque origin', 'null'],
            ['no Origin', undefined],
        ])('answers a preflight with %s 204 without CORS headers', async (_, origin) => {
            const { send } = cors()
            const response = await send(preflight(origin))
            expect(response.status).toBe(204)
            expect(response.headers.get('vary')).toBe('Origin')
            expect(corsHeaders(response)).toStrictEqual(NONE)
        })

        it('echoes an origin the product lists on success, and nothing else', async () => {
            const { send } = cors()
            const response = await send(post(form(await casdoorToken()), FORM, { origin: ACME_ORIGIN }))
            expect(corsHeaders(response)).toStrictEqual(allowed(ACME_ORIGIN))
            await expectIssued(response)
        })

        it.each([
            ['an origin only another product lists', GLOBEX_ORIGIN],
            ['an origin no product lists', 'https://evil.example'],
            ['a listed origin in another case', 'https://CN.acme.example'],
        ])('still exchanges for %s, without CORS headers', async (_, origin) => {
            const { send } = cors()
            const response = await send(post(form(await casdoorToken()), FORM, { origin }))
            expect(corsHeaders(response)).toStrictEqual(NONE)
            await expectIssued(response)
        })

        it('echoes a listed origin on a bad_signature error', async () => {
            const { send, logs } = cors()
            const token = await signToken(keys.other, casdoorClaims(), { kid: keys.casdoor.kid })
            const response = await send(post(form(token), FORM, { origin: ACME_ORIGIN }))
            expect(corsHeaders(response)).toStrictEqual(allowed(ACME_ORIGIN))
            await expectError(response, 400, 'invalid_request', NOT_ACCEPTABLE)
            expect(logs).toEqual([line(400, 'bad_signature', { product: 'acme', idp: 'casdoor' })])
        })

        it('echoes a listed origin on an unexpected error thrown after the product is resolved', async () => {
            const token = await casdoorToken()
            const { send, logs } = cors({
                randomUUID: () => {
                    throw new Error(`no randomness for ${token}`)
                },
            })
            const response = await send(post(form(token), FORM, { origin: ACME_ORIGIN }))
            const text = await response.clone().text()
            expect(corsHeaders(response)).toStrictEqual(allowed(ACME_ORIGIN))
            await expectError(response, 500, 'server_error', FAILED)
            expect(logs).toEqual([line(500, 'internal_error', { product: 'acme', idp: 'casdoor' })])
            expect(text + JSON.stringify(logs)).not.toContain(token.split('.')[1])
        })

        it.each([
            ['untrusted_issuer', 400, () => casdoorToken({ iss: 'https://evil.example' }), undefined],
            ['bad_uid', 400, () => casdoorToken({ uid: 'admin' }), 'casdoor'],
            ['jwks_unavailable', 503, () => casdoorToken(), 'casdoor'],
        ] satisfies [LogCode, number, () => Promise<string>, string | undefined][])(
            'echoes a listed origin on a %s error',
            async (code, status, token, idp) => {
                const { send, logs } = cors({}, code === 'jwks_unavailable' ? () => new Response(null, { status: 500 }) : undefined)
                const response = await send(post(form(await token()), FORM, { origin: ACME_ORIGIN }))
                expect(response.status).toBe(status)
                expect(corsHeaders(response)).toStrictEqual(allowed(ACME_ORIGIN))
                expect(logs).toEqual([line(status, code, idp === undefined ? { product: 'acme' } : { product: 'acme', idp })])
            },
        )

        it.each([
            ['a bad content type', 'text/plain', 400, (token: string) => form(token)],
            ['a body over 16 KiB', FORM, 413, (token: string) => `${form(token)}&pad=`.padEnd(MAX_BODY_BYTES + 1, 'a')],
            ['a scope', FORM, 400, (token: string) => form(token, set('scope', 'openid'))],
            ['an unknown audience', FORM, 400, (token: string) => form(token, set('audience', 'initech'))],
        ])('gives no CORS headers on an error before the product is resolved: %s', async (_, contentType, status, body) => {
            const { send } = cors()
            const response = await send(post(body(await casdoorToken()), contentType, { origin: ACME_ORIGIN }))
            expect(response.status).toBe(status)
            expect(response.headers.get('vary')).toBe('Origin')
            expect(corsHeaders(response)).toStrictEqual(NONE)
        })

        it('leaves an unexpected error before the product is resolved to handle, without CORS headers', async () => {
            const { send, logs } = cors()
            const body = new ReadableStream<Uint8Array>({
                pull(controller) {
                    controller.error(new Error('connection reset'))
                },
            })
            const response = await send(new Request(TOKEN_URL, { method: 'POST', headers: { 'content-type': FORM, origin: ACME_ORIGIN }, body }))
            expect(corsHeaders(response)).toStrictEqual(NONE)
            await expectError(response, 500, 'server_error', FAILED)
            expect(logs).toEqual([line(500, 'internal_error')])
        })

        it('carries Vary: Origin on every response', async () => {
            const { send } = cors()
            const token = await casdoorToken()
            const requests = [
                preflight(ACME_ORIGIN),
                preflight('https://evil.example'),
                preflight(),
                post(form(token), FORM, { origin: ACME_ORIGIN }),
                post(form(token), FORM, { origin: 'https://evil.example' }),
                post(form(token)),
                post(form(token), 'application/json', { origin: ACME_ORIGIN }),
                post(form('not-a-jwt'), FORM, { origin: ACME_ORIGIN }),
                post(form(token, set('audience', 'initech')), FORM, { origin: ACME_ORIGIN }),
            ]
            for (const request of requests) expect((await send(request)).headers.get('vary')).toBe('Origin')
        })
    })

    describe('user ids', () => {
        const DEPLOYMENTS: Record<string, Deployment> = { 'https://clerk.acme.example': 'clerk', 'https://casdoor.example': 'casdoor' }

        it.each(golden.userIds)('gives the golden sub for $case', async (entry) => {
            const deployment = DEPLOYMENTS[entry.issuer]
            expect(deployment).toBeDefined()
            // An entry without uid sends no uid claim, so the default Casdoor uid is removed
            const claims = { iss: entry.issuer, sub: entry.subject, uid: 'uid' in entry ? entry.uid : undefined }
            const token = deployment === 'clerk' ? await clerkToken(claims) : await casdoorToken(claims)
            const { send } = setup(deployment)
            expect(decodeJwt(await expectIssued(await send(post(form(token))))).sub).toBe(entry.expected)
        })

        it.each(golden.malformedUids)('rejects the $case uid override as bad_uid', async ({ uid }) => {
            const { send, logs } = setup()
            await expectError(await send(post(form(await clerkToken({ uid })))), 400, 'invalid_request', NOT_ACCEPTABLE)
            expect(logs).toEqual([line(400, 'bad_uid', { product: 'acme', idp: 'clerk-acme' })])
        })
    })

    describe('log line', () => {
        it('carries the product once resolved and the IdP once the binding is found', async () => {
            const { send, logs } = setup()
            await send(post(form(await clerkToken(), set('audience', 'globex'))))
            await send(post(form(await clerkToken({ iss: 'https://evil.example' }))))
            await send(post(form(await forgedClerkToken())))
            await send(post(form(await clerkToken())))
            expect(logs).toEqual([
                line(400, 'unknown_product'),
                line(400, 'untrusted_issuer', { product: 'acme' }),
                line(400, 'bad_signature', { product: 'acme', idp: 'clerk-acme' }),
                { route: 'token', status: 200, ms: 0, outcome: 'ok', product: 'acme', idp: 'clerk-acme' },
            ])
        })

        it('never carries a token, a profile value or an id, and no error body echoes the token', async () => {
            const { send, logs } = setup()
            const badUid = 'b2d6a1c4-5e7f-4a8b-9c0d'
            const tokens = [
                await clerkToken({ sub: CLERK_SUBJECT }),
                await forgedClerkToken({ sub: CLERK_SUBJECT }),
                await clerkToken({ sub: CLERK_SUBJECT, uid: badUid }),
                await clerkToken({ sub: CLERK_SUBJECT, iss: 'https://evil.example' }),
            ]
            const responses: Response[] = []
            for (const token of tokens) responses.push(await send(post(form(token))))
            const [issued, ...rejected] = responses
            const accessToken = await expectIssued(issued!)
            const bodies = await Promise.all(rejected.map((response) => response.text()))
            const serialized = JSON.stringify(logs)
            const secrets = [
                ...tokens.flatMap((token) => [token, ...token.split('.')]),
                accessToken,
                ...accessToken.split('.'),
                'ada@acme.example',
                'Ada Lovelace',
                'https://img.clerk.example/ada.png',
                CLERK_SUBJECT,
                CLERK_USER,
                badUid,
                'https://evil.example',
            ]
            for (const secret of secrets) expect(serialized).not.toContain(secret)
            for (const body of bodies) for (const token of tokens) for (const part of token.split('.')) expect(body).not.toContain(part)
        })
    })
})
