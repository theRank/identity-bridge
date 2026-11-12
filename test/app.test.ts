import { describe, expect, it } from 'vitest'
import { dispatch, handle, type Routes } from '../src/app'
import type { Deps, RouteContext, RouteHandler, Runtime, RuntimeFailure } from '../src/types'
import { fakeDeps } from './helpers/deps'

// Handlers here are fakes, so the runtime's content is never read
const runtime = { config: {}, keys: {}, webhookSecret: () => 'unused' } as unknown as Runtime
const failure: RuntimeFailure = { reason: 'missing webhook secret for source clerk-acme' }

const request = (method: string, path: string) => new Request(`https://bridge.example${path}`, { method })

interface Call {
    route: keyof Routes
    request: Request
    runtime: Runtime
    deps: Deps
    ctx: RouteContext
}

function fakeRoutes(answer: RouteHandler = async () => new Response(null, { status: 204 })) {
    const calls: Call[] = []
    const record =
        (route: keyof Routes): RouteHandler =>
        (request, runtime, deps, ctx) => {
            calls.push({ route, request, runtime, deps, ctx: { ...ctx } })
            return answer(request, runtime, deps, ctx)
        }
    const routes: Routes = { token: record('token'), jwks: record('jwks'), health: record('health'), webhooks: record('webhooks') }
    return { routes, calls }
}

describe('routing', () => {
    it.each([
        ['GET', '/'],
        ['GET', '/unknown'],
        ['POST', '/token/'],
        ['POST', '/Token'],
        ['GET', '/healthz/'],
        ['GET', '/.well-known/jwks'],
        ['GET', '/.well-known/jwks.json/'],
        ['POST', '/webhooks'],
        ['POST', '/webhooks/'],
        ['POST', '/webhooks/a/b'],
        ['POST', '/webhooks/a/'],
        ['POST', '/webhooks//a'],
        ['GET', '/webhooks/a/b'],
    ])('%s %s is 404 with an empty body, whether or not the runtime loaded', async (method, path) => {
        for (const loaded of [runtime, failure]) {
            const { deps, logs } = fakeDeps()
            const response = await handle(request(method, path), loaded, deps)
            expect(response.status).toBe(404)
            expect(response.headers.get('content-type')).toBeNull()
            expect(await response.text()).toBe('')
            expect(logs).toEqual([{ route: 'other', status: 404, ms: 0, outcome: 'rejected' }])
        }
    })

    it.each([
        ['GET', '/token', 'token', 'POST, OPTIONS'],
        ['PUT', '/token', 'token', 'POST, OPTIONS'],
        ['DELETE', '/token', 'token', 'POST, OPTIONS'],
        ['POST', '/.well-known/jwks.json', 'jwks', 'GET'],
        ['HEAD', '/.well-known/jwks.json', 'jwks', 'GET'],
        ['POST', '/healthz', 'health', 'GET'],
        ['HEAD', '/healthz', 'health', 'GET'],
        ['GET', '/webhooks/x', 'webhook', 'POST'],
        ['OPTIONS', '/webhooks/clerk-acme', 'webhook', 'POST'],
    ])('%s %s is 405 with Allow, before failure mode', async (method, path, route, allow) => {
        for (const loaded of [runtime, failure]) {
            const { deps, logs } = fakeDeps()
            const response = await handle(request(method, path), loaded, deps)
            expect(response.status).toBe(405)
            expect(response.headers.get('allow')).toBe(allow)
            expect(response.headers.get('content-type')).toBeNull()
            expect(await response.text()).toBe('')
            const source = route === 'webhook' ? { source: path.slice('/webhooks/'.length) } : {}
            expect(logs).toEqual([{ route, status: 405, ms: 0, outcome: 'rejected', ...source }])
        }
    })

    it('checks the webhook method before the source reaches any handler', async () => {
        const { routes, calls } = fakeRoutes()
        const { deps } = fakeDeps()
        const response = await dispatch(request('GET', '/webhooks/no-such-source'), runtime, deps, routes)
        expect(response.status).toBe(405)
        expect(calls).toEqual([])
    })

    it.each([
        ['POST', '/token', 'token', 'token'],
        ['OPTIONS', '/token', 'token', 'token'],
        ['GET', '/.well-known/jwks.json', 'jwks', 'jwks'],
        ['GET', '/healthz', 'health', 'health'],
        ['GET', '/healthz?probe=1', 'health', 'health'],
        ['POST', '/webhooks/clerk-acme', 'webhooks', 'webhook'],
    ] as const)('%s %s reaches the %s handler', async (method, path, handler, route) => {
        const { routes, calls } = fakeRoutes()
        const { deps, logs } = fakeDeps()
        const incoming = request(method, path)
        const response = await dispatch(incoming, runtime, deps, routes)
        expect(response.status).toBe(204)
        expect(calls).toHaveLength(1)
        expect(calls[0]!.route).toBe(handler)
        expect(calls[0]!.request).toBe(incoming)
        expect(calls[0]!.runtime).toBe(runtime)
        expect(calls[0]!.deps).toBe(deps)
        expect(logs.map((line) => line.route)).toEqual([route])
    })

    it('gives the webhook handler its source in the context, and others an empty context', async () => {
        const { routes, calls } = fakeRoutes()
        const { deps } = fakeDeps()
        await dispatch(request('POST', '/webhooks/clerk-acme'), runtime, deps, routes)
        await dispatch(request('POST', '/token'), runtime, deps, routes)
        expect(calls.map((call) => call.ctx)).toEqual([{ source: 'clerk-acme' }, {}])
    })

    it('takes the source literally: neither decoded nor case-folded', async () => {
        const { routes, calls } = fakeRoutes()
        const { deps } = fakeDeps()
        await dispatch(request('POST', '/webhooks/a%2Fb'), runtime, deps, routes)
        await dispatch(request('POST', '/webhooks/Clerk-Acme'), runtime, deps, routes)
        expect(calls.map((call) => call.ctx.source)).toEqual(['a%2Fb', 'Clerk-Acme'])
    })
})

describe('runtime failure', () => {
    it('answers /healthz 503 unavailable', async () => {
        const { deps, logs } = fakeDeps()
        const response = await handle(request('GET', '/healthz'), failure, deps)
        expect(response.status).toBe(503)
        expect(response.headers.get('content-type')).toBe('application/json')
        expect(await response.json()).toEqual({ status: 'unavailable' })
        expect(logs).toEqual([{ route: 'health', status: 503, ms: 0, outcome: 'error', code: 'runtime_unavailable' }])
    })

    it.each(['POST', 'OPTIONS'])('answers %s /token 500 server_error with the no-store headers and Vary: Origin', async (method) => {
        const { deps, logs } = fakeDeps()
        const response = await handle(request(method, '/token'), failure, deps)
        expect(response.status).toBe(500)
        expect(await response.json()).toEqual({ error: 'server_error', error_description: 'The service failed.' })
        expect(response.headers.get('cache-control')).toBe('no-store')
        expect(response.headers.get('pragma')).toBe('no-cache')
        expect(response.headers.get('vary')).toBe('Origin')
        expect(logs).toEqual([{ route: 'token', status: 500, ms: 0, outcome: 'error', code: 'runtime_unavailable' }])
    })

    it('answers the JWKS 500 with an empty body', async () => {
        const { deps, logs } = fakeDeps()
        const response = await handle(request('GET', '/.well-known/jwks.json'), failure, deps)
        expect(response.status).toBe(500)
        expect(await response.text()).toBe('')
        expect(logs).toEqual([{ route: 'jwks', status: 500, ms: 0, outcome: 'error', code: 'runtime_unavailable' }])
    })

    it('answers a webhook 500 with an empty body and logs its source', async () => {
        const { deps, logs } = fakeDeps()
        const response = await handle(request('POST', '/webhooks/clerk-acme'), failure, deps)
        expect(response.status).toBe(500)
        expect(await response.text()).toBe('')
        expect(logs).toEqual([{ route: 'webhook', status: 500, ms: 0, outcome: 'error', code: 'runtime_unavailable', source: 'clerk-acme' }])
    })

    it('never calls a handler, and keeps the reason out of responses and log lines', async () => {
        const { routes, calls } = fakeRoutes()
        const { deps, logs } = fakeDeps()
        const bodies: string[] = []
        for (const [method, path] of [
            ['POST', '/token'],
            ['OPTIONS', '/token'],
            ['GET', '/.well-known/jwks.json'],
            ['GET', '/healthz'],
            ['POST', '/webhooks/clerk-acme'],
        ] as const) {
            bodies.push(await (await dispatch(request(method, path), failure, deps, routes)).text())
        }
        expect(calls).toEqual([])
        expect(logs).toHaveLength(5)
        expect(JSON.stringify([bodies, logs])).not.toContain('missing webhook secret')
    })
})

describe('unexpected errors', () => {
    const TOKEN_LIKE = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl'
    const throwing: RouteHandler = async () => {
        throw new Error(`could not parse ${TOKEN_LIKE}`)
    }

    it('answers /healthz 503 unavailable', async () => {
        const { routes } = fakeRoutes(throwing)
        const { deps, logs } = fakeDeps()
        const response = await dispatch(request('GET', '/healthz'), runtime, deps, routes)
        expect(response.status).toBe(503)
        expect(await response.json()).toEqual({ status: 'unavailable' })
        expect(logs).toEqual([{ route: 'health', status: 503, ms: 0, outcome: 'error', code: 'internal_error' }])
    })

    it('answers /token 500 server_error with the no-store headers and Vary: Origin', async () => {
        const { routes } = fakeRoutes(throwing)
        const { deps, logs } = fakeDeps()
        const response = await dispatch(request('POST', '/token'), runtime, deps, routes)
        expect(response.status).toBe(500)
        expect(await response.json()).toEqual({ error: 'server_error', error_description: 'The service failed.' })
        expect(response.headers.get('cache-control')).toBe('no-store')
        expect(response.headers.get('pragma')).toBe('no-cache')
        expect(response.headers.get('vary')).toBe('Origin')
        expect(logs).toEqual([{ route: 'token', status: 500, ms: 0, outcome: 'error', code: 'internal_error' }])
    })

    it.each([
        ['GET', '/.well-known/jwks.json', { route: 'jwks' }],
        ['POST', '/webhooks/clerk-acme', { route: 'webhook', source: 'clerk-acme' }],
    ])('answers %s %s 500 with an empty body', async (method, path, logged) => {
        const { routes } = fakeRoutes(throwing)
        const { deps, logs } = fakeDeps()
        const response = await dispatch(request(method, path), runtime, deps, routes)
        expect(response.status).toBe(500)
        expect(await response.text()).toBe('')
        expect(logs).toEqual([{ ...logged, status: 500, ms: 0, outcome: 'error', code: 'internal_error' }])
    })

    it('catches a handler that throws before returning a promise', async () => {
        const { routes } = fakeRoutes((() => {
            throw new Error('sync')
        }) as RouteHandler)
        const { deps, logs } = fakeDeps()
        const response = await dispatch(request('GET', '/.well-known/jwks.json'), runtime, deps, routes)
        expect(response.status).toBe(500)
        expect(logs).toEqual([{ route: 'jwks', status: 500, ms: 0, outcome: 'error', code: 'internal_error' }])
    })

    it('keeps what the route learnt before the error, replaces its code, and never logs the error', async () => {
        const { routes } = fakeRoutes(async (_request, _runtime, _deps, ctx) => {
            ctx.product = 'acme'
            ctx.idp = 'clerk-acme'
            ctx.code = 'bad_signature'
            throw new Error(`could not parse ${TOKEN_LIKE}`)
        })
        const { deps, logs } = fakeDeps()
        const response = await dispatch(request('POST', '/token'), runtime, deps, routes)
        expect(logs).toEqual([{ route: 'token', status: 500, ms: 0, outcome: 'error', code: 'internal_error', product: 'acme', idp: 'clerk-acme' }])
        expect(JSON.stringify(logs)).not.toContain(TOKEN_LIKE)
        expect(await response.text()).not.toContain(TOKEN_LIKE)
    })
})

describe('log line', () => {
    it('is emitted exactly once per request', async () => {
        const { routes } = fakeRoutes()
        const { routes: broken } = fakeRoutes(async () => {
            throw new Error('boom')
        })
        const { deps, logs } = fakeDeps()
        await dispatch(request('GET', '/nowhere'), runtime, deps, routes)
        await dispatch(request('GET', '/token'), runtime, deps, routes)
        await dispatch(request('GET', '/healthz'), runtime, deps, routes)
        await dispatch(request('GET', '/healthz'), failure, deps, routes)
        await dispatch(request('POST', '/webhooks/clerk-acme'), runtime, deps, broken)
        expect(logs.map((line) => [line.route, line.status])).toEqual([
            ['other', 404],
            ['token', 405],
            ['health', 204],
            ['health', 503],
            ['webhook', 500],
        ])
    })

    it.each([
        [200, 'ok'],
        [202, 'ok'],
        [204, 'ok'],
        [400, 'rejected'],
        [401, 'rejected'],
        [404, 'rejected'],
        [413, 'rejected'],
        [500, 'error'],
        [501, 'error'],
        [502, 'error'],
        [503, 'error'],
    ])('has outcome for status %i: %s', async (status, outcome) => {
        const { routes } = fakeRoutes(async () => new Response(null, { status }))
        const { deps, logs } = fakeDeps()
        await dispatch(request('POST', '/token'), runtime, deps, routes)
        expect(logs).toEqual([{ route: 'token', status, ms: 0, outcome }])
    })

    it('carries what the route put in the context', async () => {
        const { routes } = fakeRoutes(async (_request, _runtime, _deps, ctx) => {
            ctx.idp = 'clerk-acme'
            ctx.code = 'delivery_failed'
            ctx.delivered = 1
            ctx.failed = 2
            return Response.json({}, { status: 502 })
        })
        const { deps, logs } = fakeDeps()
        await dispatch(request('POST', '/webhooks/clerk-acme'), runtime, deps, routes)
        expect(logs).toEqual([
            {
                route: 'webhook',
                status: 502,
                ms: 0,
                outcome: 'error',
                code: 'delivery_failed',
                source: 'clerk-acme',
                idp: 'clerk-acme',
                delivered: 1,
                failed: 2,
            },
        ])
    })

    it('measures ms with deps.now()', async () => {
        const fake = fakeDeps()
        const { routes } = fakeRoutes(async () => {
            fake.advance(42)
            return new Response(null, { status: 204 })
        })
        await dispatch(request('GET', '/healthz'), runtime, fake.deps, routes)
        expect(fake.logs.map((line) => line.ms)).toEqual([42])
    })
})
