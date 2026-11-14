import { env, exports } from 'cloudflare:workers'
import { calculateJwkThumbprint } from 'jose'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { resetJwksCache } from '../src/idp/jwks'
import worker, { type Env } from '../src/runtimes/workers'
import { fakeFetch } from './helpers/fetch'
import { clerkClaims, signToken } from './helpers/idp'
import { idpJwks, rsaKeyPair } from './helpers/keys'
import { expectFailureMode, expectServing, FORM, type Send } from './helpers/runtime'
import { resignClerk } from './helpers/webhooks'
import created from './fixtures/clerk/user-created.json'

const BASE = 'https://id.acme.example'
const JWKS_URI = 'https://clerk.acme.example/.well-known/jwks.json'
const EVENTS_URL = 'https://api.acme.example/identity/events'

// The bindings of vitest.config.ts: a test configuration with one Clerk webhook source, its secret and a
// signing key generated for the run
interface Bindings extends Env {
    BRIDGE_CONFIG: string
    SIGNING_KEYS: string
}

const bindings = env as unknown as Bindings
const active = JSON.parse(bindings.SIGNING_KEYS).active as JsonWebKey
const kid = await calculateJwkThumbprint({ kty: active.kty!, crv: active.crv!, x: active.x!, y: active.y! })

afterEach(() => {
    vi.restoreAllMocks()
    resetJwksCache()
})

// Through the Worker's own entry point, with the bindings it is deployed with
const viaSelf: Send = (path, init) => exports.default.fetch(`${BASE}${path}`, init)

// Straight to the handler, with bindings of the test's choosing
function viaHandler(variant: Env): Send {
    return (path, init) => worker.fetch(new Request(`${BASE}${path}`, init), variant)
}

function captureLogs(): () => Record<string, unknown>[] {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    return () => log.mock.calls.map(([text]) => JSON.parse(String(text)) as Record<string, unknown>)
}

function nowSec(): number {
    return Math.floor(Date.now() / 1000)
}

function exchangeBody(subjectToken: string): URLSearchParams {
    return new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: subjectToken,
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        audience: 'acme',
    })
}

describe('Workers entry', () => {
    it('serves the runtime loaded from its bindings', async () => {
        captureLogs()

        await expectServing(viaSelf, kid)
    })

    it('authenticates a webhook with the secret bound as WEBHOOK_SECRET_<SOURCE>', async () => {
        captureLogs()
        const { fetch, calls } = fakeFetch(() => new Response(null, { status: 202 }))
        vi.spyOn(globalThis, 'fetch').mockImplementation(fetch as typeof globalThis.fetch)
        const delivery = await resignClerk(created, { timestamp: String(nowSec()) })

        const response = await viaSelf('/webhooks/clerk-acme', { method: 'POST', headers: delivery.headers, body: delivery.body })

        expect(response.status).toBe(200)
        expect(await response.json()).toEqual({ delivered: ['acme'], failed: [] })
        expect(calls.map((call) => call.url)).toEqual([EVENTS_URL])
    })

    // The IdP key sets are cached by the parsed configuration, so a second load would fetch them again
    it('loads the runtime once per isolate', async () => {
        captureLogs()
        const pair = await rsaKeyPair()
        const { fetch, calls } = fakeFetch(() => Response.json(idpJwks(pair)))
        vi.spyOn(globalThis, 'fetch').mockImplementation(fetch as typeof globalThis.fetch)
        const now = nowSec()
        const token = await signToken(pair, clerkClaims({ iat: now - 10, nbf: now - 20, exp: now + 50 }))

        for (let attempt = 0; attempt < 2; attempt++) {
            const response = await viaSelf('/token', { method: 'POST', headers: FORM, body: exchangeBody(token) })
            expect(response.status).toBe(200)
        }

        expect(calls.map((call) => call.url)).toEqual([JWKS_URI])
    })

    describe('in failure mode', () => {
        function without(...names: (keyof Env)[]): Env {
            const variant: Env = { ...bindings }
            for (const name of names) delete variant[name]
            return variant
        }

        it.each<[string, () => Env, string]>([
            ['without a configuration', () => without('BRIDGE_CONFIG'), 'missing BRIDGE_CONFIG'],
            ['with an invalid configuration', () => ({ ...bindings, BRIDGE_CONFIG: '{"issuer": "http://id.acme.example"}' }), 'config: issuer: must be an https URL'],
            ['without signing keys', () => without('SIGNING_KEYS'), 'missing SIGNING_KEYS'],
            ['with a broken key', () => ({ ...bindings, SIGNING_KEYS: JSON.stringify({ active: { ...active, d: undefined } }) }), 'SIGNING_KEYS.active: private key required'],
            ['without the secret of a webhook source', () => without('WEBHOOK_SECRET_CLERK_ACME'), 'missing webhook secret for source clerk-acme'],
        ])('%s, logging why once', async (_, variant, reason) => {
            const logs = captureLogs()

            await expectFailureMode(viaHandler(variant()))

            const failures = logs().filter((line) => 'event' in line)
            expect(failures).toEqual([{ event: 'runtime_load_failed', reason }])
            const requests = logs().filter((line) => !('event' in line) && line.status !== 404 && line.status !== 405)
            expect(requests).toHaveLength(4)
            for (const line of requests) expect(line).toMatchObject({ outcome: 'error', code: 'runtime_unavailable' })
        })

        it('with signing keys that are not JSON, logging no part of the key', async () => {
            const logs = captureLogs()

            await expectFailureMode(viaHandler({ ...bindings, SIGNING_KEYS: bindings.SIGNING_KEYS.slice(0, -2) }))

            expect(logs().filter((line) => 'event' in line)).toEqual([{ event: 'runtime_load_failed', reason: 'SIGNING_KEYS: invalid JSON' }])
            const text = JSON.stringify(logs())
            for (let index = 0; index + 6 <= active.d!.length; index++) expect(text).not.toContain(active.d!.slice(index, index + 6))
        })
    })
})
