import { createLocalJWKSet, decodeJwt, jwtVerify, type JSONWebKeySet } from 'jose'
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { handle } from '../src/app'
import { parseConfig } from '../src/config'
import { deriveUserId } from '../src/ids'
import { importSigningKeys } from '../src/keys'
import type { Deps, LogCode, LogLine, Runtime, SigningKeys } from '../src/types'
import { casdoorConfig, clerkConfig } from './helpers/config'
import { fakeDeps } from './helpers/deps'
import { fakeFetch, hang, type FetchCall, type Responder } from './helpers/fetch'
import { bridgeSigningKeys } from './helpers/keys'
import {
    CASDOOR_SECRET,
    casdoorDelivery,
    CLERK_NOW_MS,
    CLERK_SECRET,
    deliveryRequest,
    editCasdoor,
    resignClerk,
    type CasdoorFixture,
    type Delivery,
    type Doc,
} from './helpers/webhooks'
import golden from './fixtures/golden-ids.json'
import deleteOwnAccount from './fixtures/casdoor/delete-own-account.json'
import deleteByAdminNullProperties from './fixtures/casdoor/delete-user-by-admin-null-properties.json'
import deleteByAdmin from './fixtures/casdoor/delete-user-by-admin.json'
import deleteByAppCredentials from './fixtures/casdoor/delete-user-by-app-credentials.json'
import deleteByGlobalAdmin from './fixtures/casdoor/delete-user-by-global-admin.json'
import deleteByOtherOrgAdmin from './fixtures/casdoor/delete-user-by-other-org-admin.json'
import deleteBySelf from './fixtures/casdoor/delete-user-by-self.json'
import deniedForOtherOrgAdmin from './fixtures/casdoor/delete-user-denied-for-other-org-admin.json'
import deniedForUser from './fixtures/casdoor/delete-user-denied-for-user.json'
import rejectedByController from './fixtures/casdoor/delete-user-rejected-by-controller.json'
import loginOauthSignup from './fixtures/casdoor/login-oauth-signup.json'
import newUserOauthSignup from './fixtures/casdoor/new-user-oauth-signup.json'
import newUserSignup from './fixtures/casdoor/new-user-signup.json'
import signup from './fixtures/casdoor/signup.json'
import updateBySelf from './fixtures/casdoor/update-user-by-self.json'
import clerkCreatedWithoutExternalId from './fixtures/clerk/user-created-without-external-id.json'
import clerkCreated from './fixtures/clerk/user-created.json'
import clerkDeletedWithoutExternalId from './fixtures/clerk/user-deleted-without-external-id.json'
import clerkDeleted from './fixtures/clerk/user-deleted.json'
import clerkUpdated from './fixtures/clerk/user-updated.json'

type Deployment = 'clerk' | 'casdoor'

const MAX_BODY_BYTES = 262144
const NOW_SEC = CLERK_NOW_MS / 1000
const SECRETS: Record<string, string> = { 'clerk-acme': CLERK_SECRET, 'casdoor-acme': CASDOOR_SECRET }
const SOURCES: Record<Deployment, { source: string; idp: string; issuer: string; idpIssuer: string; events: string }> = {
    clerk: {
        source: 'clerk-acme',
        idp: 'clerk-acme',
        issuer: 'https://id.acme.example',
        idpIssuer: 'https://clerk.acme.example',
        events: 'https://api.acme.example/identity/events',
    },
    casdoor: {
        source: 'casdoor-acme',
        idp: 'casdoor',
        issuer: 'https://id.cn.acme.example',
        idpIssuer: 'https://casdoor.example',
        events: 'https://api.cn.acme.example/identity/events',
    },
}
const GLOBEX_EVENTS = 'https://api.globex.example/identity/events'
const NONE = { delivered: [], failed: [] }
const SECEVENT = 'application/secevent+jwt'

// The Clerk user with an external_id, and the deleted Casdoor user with properties.uid and her admin
const ADA_UID = '2f6d1c8e-4b7a-4e3f-9a5d-7c1b0e9f8a6d'
const ALICE = 'd75162f2-693a-408e-92d1-65d71d8697e0'
const ALICE_UID = '39ca13d1-4dd9-4bdf-ad90-b2ae382c6b6c'
const ACME_ADMIN = 'a4d62447-e463-419e-9ec7-963cdb979adc'

let keys: SigningKeys

beforeAll(async () => {
    keys = await importSigningKeys((await bridgeSigningKeys(1)).json)
})

interface Setup {
    send: (request: Request) => Promise<Response>
    logs: LogLine[]
    calls: FetchCall[]
}

interface SetupOptions {
    edit?: (doc: Doc) => void
    respond?: Responder
    ignoreSignal?: boolean
    deps?: Partial<Deps>
    webhookSecret?: Runtime['webhookSecret']
}

const accepted: Responder = () => new Response(null, { status: 202 })

function setup(deployment: Deployment = 'clerk', options: SetupOptions = {}): Setup {
    const doc: Doc = deployment === 'clerk' ? clerkConfig() : casdoorConfig()
    options.edit?.(doc)
    const { fetch, calls } = fakeFetch(options.respond ?? accepted, { ignoreSignal: options.ignoreSignal ?? false })
    const { deps, logs } = fakeDeps({ fetch, now: () => CLERK_NOW_MS, ...options.deps })
    const runtime: Runtime = {
        config: parseConfig(JSON.stringify(doc)),
        keys,
        webhookSecret:
            options.webhookSecret ??
            ((id) => {
                const secret = SECRETS[id]
                if (secret === undefined) throw new Error(`no secret for ${id}`)
                return secret
            }),
    }
    return { logs, calls, send: (request) => handle(request, runtime, deps) }
}

// A second product binding the source's IdP and receiving its events. Products sharing an IdP each name their
// clients.
function twoProducts(deployment: Deployment): (doc: Doc) => void {
    return (doc) => {
        if (deployment === 'clerk') {
            doc.products.acme.idps = [{ idp: 'clerk-acme', authorizedParties: ['https://acme.example'] }]
            doc.products.globex = { idps: [{ idp: 'clerk-acme', authorizedParties: ['https://globex.example'] }], events: { url: GLOBEX_EVENTS } }
        } else {
            doc.products.globex.events = { url: GLOBEX_EVENTS }
        }
        doc.webhookSources[SOURCES[deployment].source].products = ['acme', 'globex']
    }
}

// The source's IdP maps no uid claim, so the source has no uidField
function withoutUid(deployment: Deployment): (doc: Doc) => void {
    return (doc) => {
        delete doc.idps[SOURCES[deployment].idp].claims.uid
        delete doc.webhookSources[SOURCES[deployment].source].uidField
    }
}

const clerkRequest = (delivery: Delivery, headers?: Record<string, string | null>) => deliveryRequest('clerk-acme', delivery, headers)
const casdoorRequest = (fixture: CasdoorFixture, headers?: Record<string, string | null>) =>
    deliveryRequest('casdoor-acme', casdoorDelivery(fixture), headers)

function line(deployment: Deployment, status: number, known: { code?: LogCode; delivered?: number; failed?: number } = {}): LogLine {
    const outcome = status >= 500 ? 'error' : status >= 400 ? 'rejected' : 'ok'
    return { route: 'webhook', status, ms: 0, outcome, source: SOURCES[deployment].source, idp: SOURCES[deployment].idp, ...known }
}

async function expectEmpty(response: Response, status: number): Promise<void> {
    expect(response.status).toBe(status)
    expect(response.headers.get('content-type')).toBeNull()
    expect(await response.text()).toBe('')
}

async function expectBody(response: Response, status: number, body: unknown): Promise<void> {
    expect(response.status).toBe(status)
    expect(response.headers.get('content-type')).toBe('application/json')
    expect(await response.json()).toStrictEqual(body)
}

async function verifyEvent(token: string, deployment: Deployment, audience: string) {
    const jwks = createLocalJWKSet(keys.jwks as unknown as JSONWebKeySet)
    return jwtVerify(token, jwks, { issuer: SOURCES[deployment].issuer, audience, typ: 'secevent+jwt', algorithms: ['ES256'], currentDate: new Date(CLERK_NOW_MS) })
}

// The sub of the single event token delivered for the request
async function deliveredSub(deployment: Deployment, request: Request, edit?: (doc: Doc) => void): Promise<unknown> {
    const { send, calls } = setup(deployment, edit === undefined ? {} : { edit })
    await expectBody(await send(request), 200, { delivered: ['acme'], failed: [] })
    expect(calls).toHaveLength(1)
    return decodeJwt(calls[0]!.body).sub
}

function goldenJti(idpEventId: string): string {
    const entry = golden.eventIds.find((candidate) => candidate.idpEventId === idpEventId)
    expect(entry).toBeDefined()
    return entry!.expected
}

describe('/webhooks/{source}', () => {
    describe('status table', () => {
        it('answers a method other than POST 405 with an empty body', async () => {
            const { send, logs, calls } = setup()
            const response = await send(new Request('https://id.acme.example/webhooks/clerk-acme'))
            await expectEmpty(response, 405)
            expect(response.headers.get('allow')).toBe('POST')
            expect(logs).toEqual([{ route: 'webhook', status: 405, ms: 0, outcome: 'rejected', source: 'clerk-acme' }])
            expect(calls).toHaveLength(0)
        })

        it.each(['casdoor-acme', 'globex', 'Clerk-Acme', 'clerk-acme%20', 'constructor', '__proto__', 'toString'])(
            'answers the unknown source %j 404 with an empty body, logged as unknown_source',
            async (source) => {
                const { send, logs } = setup()
                await expectEmpty(await send(deliveryRequest(source, clerkCreated)), 404)
                expect(logs).toEqual([{ route: 'webhook', status: 404, ms: 0, outcome: 'rejected', code: 'unknown_source', source }])
            },
        )

        it('answers a body over 256 KiB 413 with an empty body, logged as too_large', async () => {
            const { send, logs, calls } = setup()
            const delivery = await resignClerk({ headers: clerkCreated.headers, body: clerkCreated.body.padEnd(MAX_BODY_BYTES + 1) })
            await expectEmpty(await send(clerkRequest(delivery)), 413)
            expect(logs).toEqual([line('clerk', 413, { code: 'too_large' })])
            expect(calls).toHaveLength(0)
        })

        it('answers a failed authentication 401 with an empty body, logged as bad_webhook_auth', async () => {
            const { send, logs, calls } = setup()
            await expectEmpty(await send(clerkRequest(clerkCreated, { 'svix-signature': clerkDeleted.headers['Svix-Signature'] })), 401)
            expect(logs).toEqual([line('clerk', 401, { code: 'bad_webhook_auth' })])
            expect(calls).toHaveLength(0)
        })

        it('answers an authenticated event that is not relayed 200 with empty lists, logged as ignored', async () => {
            const { send, logs, calls } = setup()
            const delivery = await resignClerk(clerkCreated, { event: (event) => (event.type = 'session.created') })
            await expectBody(await send(clerkRequest(delivery)), 200, NONE)
            expect(logs).toEqual([line('clerk', 200, { code: 'ignored', delivered: 0, failed: 0 })])
            expect(calls).toHaveLength(0)
        })

        it('answers an authenticated but unprocessable payload 200 with empty lists, logged as bad_payload', async () => {
            const { send, logs, calls } = setup()
            const delivery = await resignClerk(clerkDeleted, { event: (event) => delete event.data.id })
            await expectBody(await send(clerkRequest(delivery)), 200, NONE)
            expect(logs).toEqual([line('clerk', 200, { code: 'bad_payload', delivered: 0, failed: 0 })])
            expect(calls).toHaveLength(0)
        })

        it('answers an invalid uid override 200 with empty lists, logged as bad_uid', async () => {
            const { send, logs, calls } = setup()
            const delivery = await resignClerk(clerkDeleted, { event: (event) => (event.data.external_id = 'admin') })
            await expectBody(await send(clerkRequest(delivery)), 200, NONE)
            expect(logs).toEqual([line('clerk', 200, { code: 'bad_uid', delivered: 0, failed: 0 })])
            expect(calls).toHaveLength(0)
        })

        it('answers 200 with every product delivered when every delivery succeeds', async () => {
            const { send, logs, calls } = setup('clerk', { edit: twoProducts('clerk') })
            await expectBody(await send(clerkRequest(clerkCreated)), 200, { delivered: ['acme', 'globex'], failed: [] })
            expect(logs).toEqual([line('clerk', 200, { delivered: 2, failed: 0 })])
            expect(calls).toHaveLength(2)
        })

        it('answers 502 naming each failed product when a delivery fails, logged as delivery_failed', async () => {
            const { send, logs } = setup('clerk', {
                edit: twoProducts('clerk'),
                respond: (call) => new Response(null, { status: call.url === GLOBEX_EVENTS ? 500 : 202 }),
            })
            await expectBody(await send(clerkRequest(clerkCreated)), 502, { delivered: ['acme'], failed: [{ product: 'globex', error: 'status 500' }] })
            expect(logs).toEqual([line('clerk', 502, { code: 'delivery_failed', delivered: 1, failed: 1 })])
        })

        it('answers 500 with an empty body in failure mode, logged as runtime_unavailable', async () => {
            const { deps, logs } = fakeDeps()
            const response = await handle(clerkRequest(clerkCreated), { reason: 'missing secret WEBHOOK_SECRET_CLERK_ACME' }, deps)
            await expectEmpty(response, 500)
            expect(logs).toEqual([{ route: 'webhook', status: 500, ms: 0, outcome: 'error', code: 'runtime_unavailable', source: 'clerk-acme' }])
        })

        it('answers 500 with an empty body for an unexpected error, logged as internal_error with what was known', async () => {
            const { send, logs, calls } = setup('clerk', {
                webhookSecret: () => {
                    throw new Error(`no secret: ${CLERK_SECRET}`)
                },
            })
            await expectEmpty(await send(clerkRequest(clerkCreated)), 500)
            expect(logs).toEqual([line('clerk', 500, { code: 'internal_error' })])
            expect(JSON.stringify(logs)).not.toContain(CLERK_SECRET)
            expect(calls).toHaveLength(0)
        })
    })

    describe('order of checks', () => {
        it('checks the source before the body size', async () => {
            const { send, logs } = setup()
            await expectEmpty(await send(deliveryRequest('globex', { headers: {}, body: 'x'.repeat(MAX_BODY_BYTES + 1) })), 404)
            expect(logs.map((logged) => logged.code)).toEqual(['unknown_source'])
        })

        it('checks the body size before authentication', async () => {
            const { send, logs } = setup()
            await expectEmpty(await send(clerkRequest({ headers: {}, body: 'x'.repeat(MAX_BODY_BYTES + 1) })), 413)
            expect(logs.map((logged) => logged.code)).toEqual(['too_large'])
        })

        it('answers 413 for a declared Content-Length over 256 KiB', async () => {
            const { send, logs } = setup()
            await expectEmpty(await send(clerkRequest(clerkCreated, { 'content-length': String(MAX_BODY_BYTES + 1) })), 413)
            expect(logs.map((logged) => logged.code)).toEqual(['too_large'])
        })

        it('accepts a signed body of exactly 256 KiB', async () => {
            const { send } = setup()
            const delivery = await resignClerk({ headers: clerkCreated.headers, body: clerkCreated.body.padEnd(MAX_BODY_BYTES) })
            await expectBody(await send(clerkRequest(delivery)), 200, { delivered: ['acme'], failed: [] })
        })

        it('authenticates before parsing', async () => {
            const { send, logs } = setup()
            await expectEmpty(await send(clerkRequest({ headers: clerkCreated.headers, body: 'not json' })), 401)
            expect(logs.map((logged) => logged.code)).toEqual(['bad_webhook_auth'])
        })

        it('authenticates a Casdoor delivery by its bearer secret', async () => {
            const { send, logs } = setup('casdoor')
            await expectEmpty(await send(casdoorRequest(newUserSignup, { authorization: 'Bearer another-secret' })), 401)
            await expectEmpty(await send(casdoorRequest(newUserSignup, { authorization: null })), 401)
            expect(logs).toEqual([line('casdoor', 401, { code: 'bad_webhook_auth' }), line('casdoor', 401, { code: 'bad_webhook_auth' })])
        })

        it.each(['', 'whsec_'])('answers 401 bad_webhook_auth for the Clerk secret %j, which decodes to an empty key', async (secret) => {
            const { send, logs, calls } = setup('clerk', { webhookSecret: () => secret })
            await expectEmpty(await send(clerkRequest(clerkCreated)), 401)
            expect(logs).toEqual([line('clerk', 401, { code: 'bad_webhook_auth' })])
            expect(calls).toHaveLength(0)
        })

        it('fails as an internal error when the Clerk secret is not base64', async () => {
            const { send, logs } = setup('clerk', { webhookSecret: () => 'whsec_not base64!' })
            await expectEmpty(await send(clerkRequest(clerkCreated)), 500)
            expect(logs).toEqual([line('clerk', 500, { code: 'internal_error' })])
        })
    })

    describe('Clerk events', () => {
        it('delivers user.created to every product as an event token that verifies against the bridge JWKS', async () => {
            const { send, calls } = setup('clerk', { edit: twoProducts('clerk') })
            await send(clerkRequest(clerkCreated))
            expect(calls.map((call) => call.url)).toEqual([SOURCES.clerk.events, GLOBEX_EVENTS])
            const picture = (JSON.parse(clerkCreated.body) as Doc).data.image_url
            for (const [call, product] of calls.map((call, index) => [call, ['acme', 'globex'][index]!] as const)) {
                expect(call.method).toBe('POST')
                expect(call.headers.get('content-type')).toBe(SECEVENT)
                expect(call.headers.get('accept')).toBe('application/json')
                expect(call.redirect).toBe('manual')
                const { payload, protectedHeader } = await verifyEvent(call.body, 'clerk', product)
                expect(protectedHeader).toStrictEqual({ alg: 'ES256', typ: 'secevent+jwt', kid: keys.kid })
                expect(payload).toStrictEqual({
                    iss: 'https://id.acme.example',
                    aud: product,
                    iat: NOW_SEC,
                    jti: goldenJti('msg_2pXk8AbCdEfGhIjKlMnOpQrStUv'),
                    txn: 'msg_2pXk8AbCdEfGhIjKlMnOpQrStUv',
                    sub: ADA_UID,
                    events: { 'urn:identity-bridge:event:user-created': { email: 'ada+clerk_test@acme.example', name: 'Bridge Test', picture } },
                })
            }
        })

        it('delivers user.updated with the current profile', async () => {
            const { send, calls } = setup()
            await expectBody(await send(clerkRequest(clerkUpdated)), 200, { delivered: ['acme'], failed: [] })
            const { payload } = await verifyEvent(calls[0]!.body, 'clerk', 'acme')
            expect(payload.txn).toBe('msg_2pXk9QwErTyUiOpAsDfGhJkLzXc')
            expect(payload.sub).toBe(ADA_UID)
            expect(payload.events).toStrictEqual({
                'urn:identity-bridge:event:user-updated': {
                    email: 'ada+clerk_test@acme.example',
                    name: 'Bridged Test',
                    picture: (JSON.parse(clerkUpdated.body) as Doc).data.image_url,
                },
            })
        })

        it('delivers user.deleted with the external_id override as sub and an empty payload', async () => {
            const { send, calls } = setup()
            await expectBody(await send(clerkRequest(clerkDeleted)), 200, { delivered: ['acme'], failed: [] })
            const { payload } = await verifyEvent(calls[0]!.body, 'clerk', 'acme')
            expect(payload).toStrictEqual({
                iss: 'https://id.acme.example',
                aud: 'acme',
                iat: NOW_SEC,
                jti: goldenJti('msg_2pXkA1b2C3d4E5f6G7h8I9j0KlM'),
                txn: 'msg_2pXkA1b2C3d4E5f6G7h8I9j0KlM',
                sub: ADA_UID,
                events: { 'urn:identity-bridge:event:user-deleted': {} },
            })
        })

        it('derives sub from the Clerk user id when there is no external_id', async () => {
            const expected = golden.userIds.find((entry) => entry.case === 'clerk user without override')!.expected
            expect(await deliveredSub('clerk', clerkRequest(clerkCreatedWithoutExternalId))).toBe(expected)
            expect(await deliveredSub('clerk', clerkRequest(clerkDeletedWithoutExternalId))).toBe(expected)
        })

        it('ignores external_id when the source has no uidField', async () => {
            const expected = await deriveUserId(SOURCES.clerk.idpIssuer, 'user_2pXkLm4NqR7sT9vW1xY3zB5cD8f')
            expect(await deliveredSub('clerk', clerkRequest(clerkDeleted), withoutUid('clerk'))).toBe(expected)
        })
    })

    describe('Casdoor events', () => {
        it('delivers new-user from a sign-up as user-created for the stored user', async () => {
            const { send, calls, logs } = setup('casdoor')
            await expectBody(await send(casdoorRequest(newUserSignup)), 200, { delivered: ['acme'], failed: [] })
            const { payload } = await verifyEvent(calls[0]!.body, 'casdoor', 'acme')
            expect(payload).toStrictEqual({
                iss: 'https://id.cn.acme.example',
                aud: 'acme',
                iat: NOW_SEC,
                jti: expect.any(String),
                txn: `new-user:${newUserSignup.body.name}`,
                sub: await deriveUserId(SOURCES.casdoor.idpIssuer, '33d91987-4b7e-4c23-8097-01a93c1873aa'),
                events: { 'urn:identity-bridge:event:user-created': { name: 'Nina Signup', picture: 'https://cdn.casbin.org/img/casbin.svg' } },
            })
            expect(calls[0]!.url).toBe(SOURCES.casdoor.events)
            expect(logs).toEqual([line('casdoor', 200, { delivered: 1, failed: 0 })])
        })

        it('delivers new-user from an OAuth sign-up with the verified email', async () => {
            const { send, calls } = setup('casdoor')
            await expectBody(await send(casdoorRequest(newUserOauthSignup)), 200, { delivered: ['acme'], failed: [] })
            const { payload } = await verifyEvent(calls[0]!.body, 'casdoor', 'acme')
            expect(payload.sub).toBe(await deriveUserId(SOURCES.casdoor.idpIssuer, '7219e2b2-93de-4e9d-9dd2-dc9b73b5f62b'))
            expect(payload.events).toStrictEqual({
                'urn:identity-bridge:event:user-created': {
                    email: 'gus@globex.example',
                    name: 'Gus Example',
                    picture: 'https://cdn.casbin.org/img/casbin.svg',
                },
            })
        })

        it("delivers an organization admin's delete-user for the deleted user, never the admin", async () => {
            const { send, calls } = setup('casdoor')
            await expectBody(await send(casdoorRequest(deleteByAdmin)), 200, { delivered: ['acme'], failed: [] })
            const { payload } = await verifyEvent(calls[0]!.body, 'casdoor', 'acme')
            expect(payload.sub).toBe(ALICE_UID)
            expect(payload.txn).toBe(`delete-user:${deleteByAdmin.body.name}`)
            expect(payload.events).toStrictEqual({ 'urn:identity-bridge:event:user-deleted': {} })

            const sub = await deliveredSub('casdoor', casdoorRequest(deleteByAdmin), withoutUid('casdoor'))
            expect(sub).toBe(await deriveUserId(SOURCES.casdoor.idpIssuer, ALICE))
            expect(sub).not.toBe(await deriveUserId(SOURCES.casdoor.idpIssuer, ACME_ADMIN))
        })

        it('gives no override for a deleted user whose properties are null', async () => {
            const expected = await deriveUserId(SOURCES.casdoor.idpIssuer, '5df95c53-cddf-4d39-82e7-0b9f39b8e1f4')
            expect(await deliveredSub('casdoor', casdoorRequest(deleteByAdminNullProperties))).toBe(expected)
        })

        it('answers bad_payload for a deletion without properties when a uidField is configured', async () => {
            const { send, logs, calls } = setup('casdoor')
            const fixture = editCasdoor(deleteByAdmin, { object: (user) => delete user.properties })
            await expectBody(await send(casdoorRequest(fixture)), 200, NONE)
            expect(logs).toEqual([line('casdoor', 200, { code: 'bad_payload', delivered: 0, failed: 0 })])
            expect(calls).toHaveLength(0)
        })

        it('answers a record with an empty name 200 with empty lists, logged as bad_payload', async () => {
            const { send, logs, calls } = setup('casdoor')
            await expectBody(await send(casdoorRequest(editCasdoor(newUserSignup, { record: (record) => (record.name = '') }))), 200, NONE)
            expect(logs).toEqual([line('casdoor', 200, { code: 'bad_payload', delivered: 0, failed: 0 })])
            expect(calls).toHaveLength(0)
        })

        it.each([
            ['signup', signup],
            ['the login of an OAuth sign-up', loginOauthSignup],
            ['delete-user by an admin of another organization', deleteByOtherOrgAdmin],
            ['delete-user by a global admin', deleteByGlobalAdmin],
            ['delete-user through application credentials', deleteByAppCredentials],
            ['delete-user by the user themselves', deleteBySelf],
            ['update-user by the user themselves', updateBySelf],
            ['delete-own-account', deleteOwnAccount],
            ['a delete-user the controller rejected', rejectedByController],
            ['a delete-user denied to a user', deniedForUser],
            ['a delete-user denied to an admin of another organization', deniedForOtherOrgAdmin],
        ])('answers %s 200 with empty lists, logged as ignored', async (_, fixture) => {
            const { send, logs, calls } = setup('casdoor')
            await expectBody(await send(casdoorRequest(fixture)), 200, NONE)
            expect(logs).toEqual([line('casdoor', 200, { code: 'ignored', delivered: 0, failed: 0 })])
            expect(calls).toHaveLength(0)
        })

        it.each([
            ['of another organization', (record: Doc) => (record.organization = 'globex')],
            ['with a failed outcome', (record: Doc) => (record.response = '{status:"error", msg:"x"}')],
        ])('answers a new-user record %s 200 with empty lists, logged as ignored', async (_, edit) => {
            const { send, logs, calls } = setup('casdoor')
            await expectBody(await send(casdoorRequest(editCasdoor(newUserOauthSignup, { record: edit }))), 200, NONE)
            expect(logs).toEqual([line('casdoor', 200, { code: 'ignored', delivered: 0, failed: 0 })])
            expect(calls).toHaveLength(0)
        })
    })

    describe('fan-out', () => {
        it('starts every delivery before any is answered', async () => {
            // Each delivery waits for its own answer, given only once every delivery has started
            const answers: (() => void)[] = []
            const { send, calls } = setup('casdoor', {
                edit: twoProducts('casdoor'),
                respond: () => new Promise<Response>((resolve) => answers.push(() => resolve(new Response(null, { status: 202 })))),
            })
            const pending = send(casdoorRequest(newUserSignup))
            await vi.waitFor(() => expect(answers).toHaveLength(2))
            expect(calls.map((call) => call.url)).toEqual([SOURCES.casdoor.events, GLOBEX_EVENTS])
            for (const answer of answers) answer()
            await expectBody(await pending, 200, { delivered: ['acme', 'globex'], failed: [] })
        })

        it('gives a redelivery the same jti, and another event another one', async () => {
            const { send, calls } = setup()
            await send(clerkRequest(clerkCreated))
            await send(clerkRequest(clerkCreated))
            await send(clerkRequest(await resignClerk(clerkCreated, { id: 'msg_2pXkRe1dEl1vErY0aBcDeFgHiJk' })))
            const jtis = calls.map((call) => decodeJwt(call.body).jti)
            expect(jtis[0]).toBe(jtis[1])
            expect(jtis[2]).not.toBe(jtis[0])
        })

        it.each([200, 201, 202, 204, 299])('counts a %i answer as delivered', async (status) => {
            const { send } = setup('clerk', { respond: () => new Response(null, { status }) })
            await expectBody(await send(clerkRequest(clerkCreated)), 200, { delivered: ['acme'], failed: [] })
        })

        it.each([
            [301, 'status 301'],
            [302, 'status 302'],
            [304, 'status 304'],
            [307, 'status 307'],
            [400, 'status 400'],
            [409, 'status 409'],
            [500, 'status 500'],
            [503, 'status 503'],
        ])('counts a %i answer as failed: %s', async (status, error) => {
            const { send } = setup('clerk', { respond: () => new Response(null, { status }) })
            await expectBody(await send(clerkRequest(clerkCreated)), 502, { delivered: [], failed: [{ product: 'acme', error }] })
        })

        it.each([
            [202, 200, { delivered: ['acme'], failed: [] }],
            [500, 502, { delivered: [], failed: [{ product: 'acme', error: 'status 500' }] }],
        ])('cancels the streamed body of a %i answer without reading it', async (answered, status, body) => {
            let cancelled = false
            const { send } = setup('clerk', {
                respond: () => {
                    // A body that never ends: reading it would stall the delivery until its timeout
                    const stream = new ReadableStream<Uint8Array>({
                        pull: () => new Promise<void>(() => {}),
                        cancel: () => {
                            cancelled = true
                        },
                    })
                    return new Response(stream, { status: answered, headers: { 'content-type': 'application/json' } })
                },
            })
            await expectBody(await send(clerkRequest(clerkCreated)), status, body)
            expect(cancelled).toBe(true)
        })

        it('never follows a redirect', async () => {
            const { send, calls } = setup('clerk', {
                respond: () => new Response(null, { status: 302, headers: { location: 'https://evil.example/collect' } }),
            })
            await expectBody(await send(clerkRequest(clerkCreated)), 502, { delivered: [], failed: [{ product: 'acme', error: 'status 302' }] })
            expect(calls.map((call) => [call.url, call.redirect])).toEqual([[SOURCES.clerk.events, 'manual']])
        })

        it('counts a delivery whose fetch rejects as network', async () => {
            const { send } = setup('clerk', {
                edit: twoProducts('clerk'),
                respond: (call) => {
                    if (call.url === GLOBEX_EVENTS) throw new TypeError('connection refused')
                    return new Response(null, { status: 202 })
                },
            })
            await expectBody(await send(clerkRequest(clerkCreated)), 502, { delivered: ['acme'], failed: [{ product: 'globex', error: 'network' }] })
        })

        it('counts a fetch that throws before returning a promise as network', async () => {
            const { send } = setup('clerk', {
                deps: {
                    fetch: (() => {
                        throw new TypeError('no fetch')
                    }) as Deps['fetch'],
                },
            })
            await expectBody(await send(clerkRequest(clerkCreated)), 502, { delivered: [], failed: [{ product: 'acme', error: 'network' }] })
        })

        it('answers 502 when every delivery fails, logged with the counts', async () => {
            const { send, logs } = setup('casdoor', { edit: twoProducts('casdoor'), respond: () => new Response(null, { status: 503 }) })
            await expectBody(await send(casdoorRequest(newUserSignup)), 502, {
                delivered: [],
                failed: [
                    { product: 'acme', error: 'status 503' },
                    { product: 'globex', error: 'status 503' },
                ],
            })
            expect(logs).toEqual([line('casdoor', 502, { code: 'delivery_failed', delivered: 0, failed: 2 })])
        })

        it('lists products in the order of the source, whichever answers first', async () => {
            let releaseAcme!: () => void
            const acmeWaits = new Promise<void>((resolve) => {
                releaseAcme = resolve
            })
            const { send } = setup('clerk', {
                edit: twoProducts('clerk'),
                respond: async (call) => {
                    if (call.url === GLOBEX_EVENTS) {
                        releaseAcme()
                        return new Response(null, { status: 500 })
                    }
                    await acmeWaits
                    return new Response(null, { status: 500 })
                },
            })
            const body = (await (await send(clerkRequest(clerkCreated))).json()) as { failed: { product: string }[] }
            expect(body.failed.map((failure) => failure.product)).toEqual(['acme', 'globex'])
        })

        describe('timeouts', () => {
            // Kept from before the timers are faked, to wait in real time for the deliveries to start
            const realSetTimeout = globalThis.setTimeout

            beforeEach(() => {
                vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
            })

            afterEach(() => {
                vi.useRealTimers()
                vi.unstubAllGlobals()
            })

            async function started(calls: FetchCall[], count: number): Promise<void> {
                for (let tries = 0; calls.length < count && tries < 400; tries++) await new Promise((resolve) => realSetTimeout(resolve, 5))
                expect(calls).toHaveLength(count)
            }

            // globex never answers; acme accepts at once
            function stalled(ignoreSignal: boolean): Setup {
                return setup('clerk', {
                    edit: twoProducts('clerk'),
                    ignoreSignal,
                    respond: (call) => (call.url === GLOBEX_EVENTS ? hang(call) : new Response(null, { status: 202 })),
                })
            }

            async function settlesAt5s(pending: Promise<Response>): Promise<Response> {
                let settled = false
                const outcome = pending.finally(() => {
                    settled = true
                })
                await vi.advanceTimersByTimeAsync(4999)
                expect(settled).toBe(false)
                await vi.advanceTimersByTimeAsync(1)
                expect(settled).toBe(true)
                return outcome
            }

            it.each([
                ['honours its signal', false],
                ['ignores its signal', true],
            ])('fails a delivery that never answers as timeout after 5 s, when the fetch %s', async (_, ignoreSignal) => {
                const { send, calls, logs } = stalled(ignoreSignal)
                const pending = send(clerkRequest(clerkCreated))
                await started(calls, 2)
                const response = await settlesAt5s(pending)
                await expectBody(response, 502, { delivered: ['acme'], failed: [{ product: 'globex', error: 'timeout' }] })
                expect(logs).toEqual([line('clerk', 502, { code: 'delivery_failed', delivered: 1, failed: 1 })])
                expect(calls[1]!.signal?.aborted).toBe(true)
            })

            it('still times out where the runtime has no AbortController, sending no signal', async () => {
                vi.stubGlobal('AbortController', undefined)
                const { send, calls } = stalled(false)
                const pending = send(clerkRequest(clerkCreated))
                await started(calls, 2)
                const response = await settlesAt5s(pending)
                await expectBody(response, 502, { delivered: ['acme'], failed: [{ product: 'globex', error: 'timeout' }] })
                expect(calls.map((call) => call.signal)).toEqual([undefined, undefined])
            })

            it('leaves no timer behind once the deliveries settle', async () => {
                const { send } = setup('clerk', { edit: twoProducts('clerk') })
                await expectBody(await send(clerkRequest(clerkCreated)), 200, { delivered: ['acme', 'globex'], failed: [] })
                expect(vi.getTimerCount()).toBe(0)
            })
        })
    })

    describe('log line', () => {
        it('carries the source, the IdP and the counts, and never payload content', async () => {
            const clerk = setup('clerk', { edit: twoProducts('clerk'), respond: (call) => new Response(null, { status: call.url === GLOBEX_EVENTS ? 500 : 202 }) })
            const casdoor = setup('casdoor')
            const badUid = await resignClerk(clerkDeleted, { event: (event) => (event.data.external_id = 'b2d6a1c4-5e7f-4a8b-9c0d') })
            const unprocessable = await resignClerk(clerkDeleted, { event: (event) => (event.data.id = 42) })
            const responses = [
                await clerk.send(clerkRequest(clerkCreated)),
                await clerk.send(clerkRequest(clerkUpdated)),
                await clerk.send(clerkRequest(badUid)),
                await clerk.send(clerkRequest(unprocessable)),
                await clerk.send(clerkRequest(clerkCreated, { 'svix-signature': 'v1,forged' })),
                await casdoor.send(casdoorRequest(newUserOauthSignup)),
                await casdoor.send(casdoorRequest(deleteByAdmin)),
                await casdoor.send(casdoorRequest(deleteBySelf)),
            ]
            const bodies = await Promise.all(responses.map((response) => response.text()))
            expect(clerk.logs).toEqual([
                line('clerk', 502, { code: 'delivery_failed', delivered: 1, failed: 1 }),
                line('clerk', 502, { code: 'delivery_failed', delivered: 1, failed: 1 }),
                line('clerk', 200, { code: 'bad_uid', delivered: 0, failed: 0 }),
                line('clerk', 200, { code: 'bad_payload', delivered: 0, failed: 0 }),
                line('clerk', 401, { code: 'bad_webhook_auth' }),
            ])
            expect(casdoor.logs).toEqual([
                line('casdoor', 200, { delivered: 1, failed: 0 }),
                line('casdoor', 200, { delivered: 1, failed: 0 }),
                line('casdoor', 200, { code: 'ignored', delivered: 0, failed: 0 }),
            ])

            const serialized = JSON.stringify([clerk.logs, casdoor.logs, bodies])
            const tokens = [...clerk.calls, ...casdoor.calls].map((call) => call.body)
            const payload = [
                ...tokens.flatMap((token) => [token, ...token.split('.')]),
                ...tokens.map((token) => decodeJwt(token).sub as string),
                ...tokens.map((token) => decodeJwt(token).jti as string),
                CLERK_SECRET,
                CASDOOR_SECRET,
                clerkCreated.headers['Svix-Id'],
                clerkCreated.headers['Svix-Signature'],
                'user_2pXkLm4NqR7sT9vW1xY3zB5cD8f',
                ADA_UID,
                'ada+clerk_test@acme.example',
                'Bridge',
                'b2d6a1c4-5e7f-4a8b-9c0d',
                'gus@globex.example',
                'Gus Example',
                '7219e2b2-93de-4e9d-9dd2-dc9b73b5f62b',
                ALICE,
                ALICE_UID,
                ACME_ADMIN,
                deleteByAdmin.body.name,
                newUserOauthSignup.body.name,
                'cdn.casbin.org',
                'img.clerk.com',
            ]
            for (const value of payload) expect(serialized).not.toContain(value)
        })
    })

    describe('user ids', () => {
        const CLERK_ISSUER = SOURCES.clerk.idpIssuer

        // Each golden subject and override, written into a created and a deleted event of the IdP
        async function goldenRequests(entry: (typeof golden.userIds)[number]): Promise<[Deployment, Request[]]> {
            if (entry.issuer === CLERK_ISSUER) {
                const edit = (event: Doc) => {
                    event.data.id = entry.subject
                    if ('uid' in entry) event.data.external_id = entry.uid
                    else delete event.data.external_id
                }
                return ['clerk', [clerkRequest(await resignClerk(clerkCreated, { event: edit })), clerkRequest(await resignClerk(clerkDeleted, { event: edit }))]]
            }
            expect(entry.issuer).toBe(SOURCES.casdoor.idpIssuer)
            const object = (user: Doc) => {
                user.id = entry.subject
                user.properties = 'uid' in entry ? { uid: entry.uid } : {}
            }
            return ['casdoor', [casdoorRequest(editCasdoor(newUserSignup, { object })), casdoorRequest(editCasdoor(deleteByAdmin, { object }))]]
        }

        it.each(golden.userIds)('gives the golden sub for $case, on created and deleted events', async (entry) => {
            const [deployment, requests] = await goldenRequests(entry)
            for (const request of requests) expect(await deliveredSub(deployment, request)).toBe(entry.expected)
        })

        it.each(golden.malformedUids)('refuses the $case uid override as bad_uid on both IdPs, delivering nothing', async ({ uid }) => {
            const clerk = setup('clerk')
            const casdoor = setup('casdoor')
            const clerkDelivery = await resignClerk(clerkDeleted, { event: (event) => (event.data.external_id = uid) })
            const casdoorFixture = editCasdoor(deleteByAdmin, { object: (user) => (user.properties = { uid }) })
            await expectBody(await clerk.send(clerkRequest(clerkDelivery)), 200, NONE)
            await expectBody(await casdoor.send(casdoorRequest(casdoorFixture)), 200, NONE)
            expect(clerk.logs).toEqual([line('clerk', 200, { code: 'bad_uid', delivered: 0, failed: 0 })])
            expect(casdoor.logs).toEqual([line('casdoor', 200, { code: 'bad_uid', delivered: 0, failed: 0 })])
            expect([...clerk.calls, ...casdoor.calls]).toHaveLength(0)
        })
    })

    describe('event ids', () => {
        it.each([
            ['user.created', clerkCreated],
            ['user.deleted', clerkDeleted],
        ])('gives the Clerk %s delivery the golden jti, with its svix-id as txn', async (_, fixture) => {
            const { send, calls } = setup()
            await send(clerkRequest(fixture))
            const claims = decodeJwt(calls[0]!.body)
            expect(claims.txn).toBe(fixture.headers['Svix-Id'])
            expect(claims.jti).toBe(goldenJti(fixture.headers['Svix-Id']))
        })

        it('gives Casdoor records the golden jti of "<action>:<name>", so a sign-up and its new-user never collide', async () => {
            const { send, calls, logs } = setup('casdoor')
            const named = (fixture: CasdoorFixture, idpEventId: string) => {
                const name = idpEventId.slice(idpEventId.indexOf(':') + 1)
                return casdoorRequest(editCasdoor(fixture, { record: (record) => (record.name = name) }))
            }
            const newUser = 'new-user:5d1c3b7a-2e4f-4a6b-8c9d-0e1f2a3b4c5d'
            const signupId = 'signup:5d1c3b7a-2e4f-4a6b-8c9d-0e1f2a3b4c5d'
            const deletion = 'delete-user:9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b'
            await send(named(signup, signupId))
            await send(named(newUserSignup, newUser))
            await send(named(deleteByAdmin, deletion))
            expect(logs.map((logged) => logged.code)).toEqual(['ignored', undefined, undefined])
            const claims = calls.map((call) => decodeJwt(call.body))
            expect(claims.map((claim) => [claim.txn, claim.jti])).toEqual([
                [newUser, goldenJti(newUser)],
                [deletion, goldenJti(deletion)],
            ])
            expect(goldenJti(newUser)).not.toBe(goldenJti(signupId))
        })
    })
})
