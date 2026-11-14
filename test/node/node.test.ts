import { Agent, request, type Server } from 'node:http'
import { calculateJwkThumbprint } from 'jose'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createNodeServer, shutdown } from '../../src/runtimes/node'
import type { Deps } from '../../src/types'
import { clerkConfig, clerkConfigJson } from '../helpers/config'
import { START_MS } from '../helpers/deps'
import { fakeFetch } from '../helpers/fetch'
import { clerkClaims, signToken } from '../helpers/idp'
import { bridgeSigningKeys, idpJwks, rsaKeyPair } from '../helpers/keys'
import { expectFailureMode, expectServing, FORM, type Send } from '../helpers/runtime'
import { CLERK_NOW_MS, CLERK_SECRET, svixSignature } from '../helpers/webhooks'
import created from '../fixtures/clerk/user-created.json'
import { ask, listen } from './http'

const JWKS_URI = 'https://clerk.acme.example/.well-known/jwks.json'
const EVENTS_URL = 'https://api.acme.example/identity/events'
const TOO_LARGE = { error: 'invalid_request', error_description: 'The request is too large.' }

const keys = await bridgeSigningKeys()
const kid = await calculateJwkThumbprint({ kty: keys.active.kty!, crv: keys.active.crv!, x: keys.active.x!, y: keys.active.y! })
const ENV = { BRIDGE_CONFIG: clerkConfigJson, SIGNING_KEYS: keys.json, WEBHOOK_SECRET_CLERK_ACME: CLERK_SECRET }

const servers: Server[] = []

afterEach(() => {
    vi.restoreAllMocks()
    for (const server of servers.splice(0)) {
        server.closeAllConnections()
        server.close()
    }
})

async function serve(env: Record<string, string | undefined>, deps: Partial<Deps> = {}) {
    const logs: string[] = []
    const { server, ready } = createNodeServer({ env, deps: { now: () => START_MS, ...deps }, log: (text) => logs.push(text) })
    servers.push(server)
    await ready
    const origin = await listen(server)
    const lines = () => logs.map((text) => JSON.parse(text) as Record<string, unknown>)
    return { origin, server, logs, lines }
}

function viaFetch(origin: string): Send {
    return (path, init) => fetch(`${origin}${path}`, init)
}

function exchangeBody(subjectToken: string, audience = 'acme'): string {
    return new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: subjectToken,
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        audience,
    }).toString()
}

// An IdP whose key set is served only once `release` is called, and which says when it was asked
async function heldIdp() {
    const pair = await rsaKeyPair()
    let release!: () => void
    let asked!: () => void
    const released = new Promise<void>((resolve) => (release = resolve))
    const inFlight = new Promise<void>((resolve) => (asked = resolve))
    const { fetch, calls } = fakeFetch(async () => {
        asked()
        await released
        return Response.json(idpJwks(pair))
    })
    return { fetch, calls, release, inFlight, token: await signToken(pair, clerkClaims()) }
}

const never = new Promise<never>(() => {})

describe('Node entry', () => {
    it('serves the runtime loaded from its environment', async () => {
        const { origin } = await serve(ENV)

        await expectServing(viaFetch(origin), kid)
    })

    // The IdP key sets are cached by the parsed configuration, so a second load would fetch them again
    it('loads the runtime once', async () => {
        const pair = await rsaKeyPair()
        const { fetch, calls } = fakeFetch(() => Response.json(idpJwks(pair)))
        const { origin } = await serve(ENV, { fetch })
        const token = await signToken(pair, clerkClaims())

        for (let attempt = 0; attempt < 2; attempt++) {
            const answer = await ask(origin, { method: 'POST', path: '/token', headers: FORM, body: [exchangeBody(token)] })
            expect(answer.status).toBe(200)
        }

        expect(calls.map((call) => call.url)).toEqual([JWKS_URI])
    })

    describe('in failure mode', () => {
        const without = (name: keyof typeof ENV) => ({ ...ENV, [name]: undefined })
        const unknownIdp = clerkConfig()
        unknownIdp.products.acme.idps[0]!.idp = 'clerk-acm'

        it.each<[string, Record<string, string | undefined>, string]>([
            ['without a configuration', without('BRIDGE_CONFIG'), 'missing BRIDGE_CONFIG'],
            ['with an invalid configuration', { ...ENV, BRIDGE_CONFIG: JSON.stringify(unknownIdp) }, 'config: products.acme.idps[0].idp: unknown idp "clerk-acm"'],
            ['without signing keys', without('SIGNING_KEYS'), 'missing SIGNING_KEYS'],
            ['with a broken key', { ...ENV, SIGNING_KEYS: JSON.stringify({ active: { ...keys.active, d: undefined } }) }, 'SIGNING_KEYS.active: private key required'],
            ['without the secret of a webhook source', without('WEBHOOK_SECRET_CLERK_ACME'), 'missing webhook secret for source clerk-acme'],
            ['with an empty webhook secret', { ...ENV, WEBHOOK_SECRET_CLERK_ACME: '' }, 'missing webhook secret for source clerk-acme'],
        ])('%s, logging why once, before any request', async (_, env, reason) => {
            const { origin, lines } = await serve(env)
            expect(lines()).toEqual([{ event: 'runtime_load_failed', reason }])

            await expectFailureMode(viaFetch(origin))

            expect(lines().filter((line) => 'event' in line)).toHaveLength(1)
            const requests = lines().filter((line) => !('event' in line) && line.status !== 404 && line.status !== 405)
            expect(requests).toHaveLength(4)
            for (const line of requests) expect(line).toMatchObject({ outcome: 'error', code: 'runtime_unavailable' })
        })

        it('with signing keys that are not JSON, logging no part of the private key', async () => {
            const { origin, logs, lines } = await serve({ ...ENV, SIGNING_KEYS: keys.json.slice(0, -2) })

            await expectFailureMode(viaFetch(origin))

            expect(lines()[0]).toEqual({ event: 'runtime_load_failed', reason: 'SIGNING_KEYS: invalid JSON' })
            const d = keys.active.d!
            for (let index = 0; index + 6 <= d.length; index++) expect(logs.join('\n')).not.toContain(d.slice(index, index + 6))
        })
    })

    describe('routes by the path alone', () => {
        it.each([
            ['a Host of the client', { path: '/healthz', headers: { host: 'evil.example' } }, 200],
            ['a Host that is no host', { path: '/healthz', headers: { host: 'a b' } }, 200],
            ['an absolute-form target', { path: 'http://evil.example/healthz' }, 200],
            ['an absolute-form target with a query', { path: 'http://evil.example/healthz?probe=1' }, 200],
            ['an absolute-form target to an unknown path', { path: 'https://id.acme.example/nope' }, 404],
            ['a path that looks like a host', { path: '//evil.example/healthz' }, 404],
        ])('ignoring %s', async (_, options, status) => {
            const { origin } = await serve(ENV)

            expect((await ask(origin, options)).status).toBe(status)
        })
    })

    it('answers HEAD /healthz with 405', async () => {
        const { origin } = await serve(ENV)
        const answer = await ask(origin, { method: 'HEAD', path: '/healthz' })

        expect(answer.status).toBe(405)
        expect(answer.headers.allow).toBe('GET')
    })

    describe('limits a /token body', () => {
        it('answering 413 to a declared oversize body before it has arrived, and closing the connection', async () => {
            const { origin, lines } = await serve(ENV)
            const answer = await ask(origin, {
                method: 'POST',
                path: '/token',
                headers: { ...FORM, 'content-length': 1024 * 1024 },
                body: ['x'.repeat(1024)],
                end: false,
            })

            expect(answer.status).toBe(413)
            expect(JSON.parse(answer.body)).toEqual(TOO_LARGE)
            expect(answer.headers.connection).toBe('close')
            expect(lines()).toEqual([expect.objectContaining({ route: 'token', status: 413, code: 'too_large' })])
        })

        it('stopping a streamed body of no declared length at the limit', async () => {
            const { origin, lines } = await serve(ENV)
            const answer = await ask(origin, {
                method: 'POST',
                path: '/token',
                headers: { ...FORM, 'transfer-encoding': 'chunked' },
                body: Array.from({ length: 5 }, () => 'x'.repeat(4096)),
                end: false,
            })

            expect(answer.status).toBe(413)
            expect(JSON.parse(answer.body)).toEqual(TOO_LARGE)
            expect(answer.headers.connection).toBe('close')
            expect(lines()).toEqual([expect.objectContaining({ route: 'token', status: 413, code: 'too_large' })])
        })
    })

    // Node itself keeps only the first of some repeated headers, such as Content-Type
    it('joins repeated headers as Headers does', async () => {
        const { origin } = await serve(ENV)
        const body = [exchangeBody('junk', 'nope')]
        const once = await ask(origin, { method: 'POST', path: '/token', headers: FORM, body })
        const twice = await ask(origin, { method: 'POST', path: '/token', headers: { 'content-type': [FORM['content-type'], FORM['content-type']] }, body })

        expect(JSON.parse(once.body)).toMatchObject({ error: 'invalid_target' })
        expect(twice.status).toBe(400)
        expect(JSON.parse(twice.body)).toEqual({ error: 'invalid_request', error_description: 'The request is malformed.' })
    })

    // Svix signs the exact bytes, so any change on the way, even to whitespace, fails the signature
    it('verifies a webhook over the exact bytes sent, split inside a character', async () => {
        const event = JSON.parse(created.body) as { data: Record<string, unknown> }
        event.data.first_name = 'Zoë'
        const body = `${JSON.stringify(event, null, 2)}\n`
        const id = created.headers['Svix-Id']
        const timestamp = created.headers['Svix-Timestamp']
        const bytes = new TextEncoder().encode(body)
        const split = bytes.indexOf(0xc3) + 1
        const { fetch, calls } = fakeFetch(() => new Response(null, { status: 202 }))
        const { origin } = await serve(ENV, { fetch, now: () => CLERK_NOW_MS })

        const answer = await ask(origin, {
            method: 'POST',
            path: '/webhooks/clerk-acme',
            headers: {
                'content-type': 'application/json',
                'content-length': bytes.byteLength,
                'svix-id': id,
                'svix-timestamp': timestamp,
                'svix-signature': await svixSignature(CLERK_SECRET, id, timestamp, body),
            },
            body: [bytes.subarray(0, split), bytes.subarray(split)],
        })

        expect(answer.status).toBe(200)
        expect(JSON.parse(answer.body)).toEqual({ delivered: ['acme'], failed: [] })
        expect(calls.map((call) => call.url)).toEqual([EVENTS_URL])
    })

    // Fetch refuses to build a Request for TRACE, so the adapter itself fails
    it('answers an empty 500 when the adapter fails, logging internal_error and no error text', async () => {
        const { origin, logs, lines } = await serve(ENV)
        const answer = await ask(origin, { method: 'TRACE', path: '/healthz' })

        expect(answer.status).toBe(500)
        expect(answer.body).toBe('')
        expect(lines()).toEqual([{ route: 'other', status: 500, ms: 0, outcome: 'error', code: 'internal_error' }])
        expect(logs.join('\n')).not.toMatch(/TRACE|unsupported/i)
    })

    it('keeps serving after a client leaves partway through a body', async () => {
        const { origin } = await serve(ENV)
        await new Promise<void>((resolve) => {
            const { hostname, port } = new URL(origin)
            const req = request({ host: hostname, port, method: 'POST', path: '/token', headers: { ...FORM, 'content-length': 100 } })
            req.on('error', () => resolve())
            req.write('grant_type=', () => setImmediate(() => req.destroy()))
        })

        expect((await fetch(`${origin}/healthz`)).status).toBe(200)
    })

    it('keeps a connection alive across requests whose bodies were read', async () => {
        const { origin } = await serve(ENV)
        const agent = new Agent({ keepAlive: true, maxSockets: 1 })
        const reused: boolean[] = []
        const send = () =>
            new Promise<number>((resolve, reject) => {
                const { hostname, port } = new URL(origin)
                const req = request({ host: hostname, port, method: 'POST', path: '/token', headers: FORM, agent })
                req.on('error', reject)
                req.on('response', (res) => {
                    reused.push(req.reusedSocket)
                    res.resume()
                    res.on('end', () => resolve(res.statusCode!))
                })
                req.end(exchangeBody('junk'))
            })

        expect([await send(), await send()]).toEqual([400, 400])
        expect(reused).toEqual([false, true])
        agent.destroy()
    })

    it('closes the connection after an answer that left the body unread', async () => {
        const { origin } = await serve(ENV)
        const answer = await ask(origin, { method: 'POST', path: '/nope', headers: { 'content-length': 1024 * 1024 }, body: ['x'.repeat(1024)], end: false })

        expect(answer.status).toBe(404)
        expect(answer.headers.connection).toBe('close')
    })

    it('times requests out as a public server should', async () => {
        const { server } = await serve(ENV)

        expect(server.headersTimeout).toBe(10_000)
        expect(server.requestTimeout).toBe(30_000)
        expect(server.keepAliveTimeout).toBe(65_000)
    })

    it('writes each log line as JSON to stdout unless told otherwise', async () => {
        const written: string[] = []
        vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
            written.push(String(chunk))
            return true
        })
        const { server, ready } = createNodeServer({ env: without(ENV, 'BRIDGE_CONFIG'), deps: { now: () => START_MS } })
        servers.push(server)
        await ready
        const origin = await listen(server)
        await fetch(`${origin}/healthz`)

        expect(written).toEqual([
            `${JSON.stringify({ event: 'runtime_load_failed', reason: 'missing BRIDGE_CONFIG' })}\n`,
            `${JSON.stringify({ route: 'health', status: 503, ms: 0, outcome: 'error', code: 'runtime_unavailable' })}\n`,
        ])
    })
})

describe('shutdown', () => {
    it('stops accepting connections and completes a request in flight', async () => {
        const idp = await heldIdp()
        const { origin, server } = await serve(ENV, { fetch: idp.fetch })
        const exchange = ask(origin, { method: 'POST', path: '/token', headers: FORM, body: [exchangeBody(idp.token)] })
        await idp.inFlight

        const stopped = shutdown(server, never)
        await expect(fetch(`${origin}/healthz`)).rejects.toThrow()
        idp.release()
        const answer = await exchange

        expect(answer.status).toBe(200)
        expect(JSON.parse(answer.body)).toMatchObject({ token_type: 'Bearer' })
        expect(answer.headers.connection).toBe('close')
        await stopped
    })

    it('closes idle connections at once', async () => {
        const { origin, server } = await serve(ENV)
        const agent = new Agent({ keepAlive: true })
        await new Promise<void>((resolve, reject) => {
            const { hostname, port } = new URL(origin)
            request({ host: hostname, port, path: '/healthz', agent }, (res) => res.resume().on('end', resolve)).on('error', reject).end()
        })

        await shutdown(server, never)
        agent.destroy()
    })

    it('closes the connections left once the deadline passes', async () => {
        const idp = await heldIdp()
        const { origin, server } = await serve(ENV, { fetch: idp.fetch })
        const exchange = ask(origin, { method: 'POST', path: '/token', headers: FORM, body: [exchangeBody(idp.token)] })
        await idp.inFlight
        let pass!: () => void
        const deadline = new Promise<void>((resolve) => (pass = resolve))

        const stopped = shutdown(server, deadline)
        pass()

        await expect(exchange).rejects.toThrow()
        await stopped
        idp.release()
    })
})

function without<T extends object>(env: T, name: keyof T): T {
    return { ...env, [name]: undefined }
}
