import { env } from 'cloudflare:workers'
import { calculateJwkThumbprint } from 'jose'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Env } from '../src/runtimes/edge'
import { expectFailureMode, expectServing, type Send } from './helpers/runtime'

const BASE = 'https://id.acme.example'

// The bindings of vitest.config.ts, handed to the ESA entry the way ESA hands over its variables
interface Bindings extends Env {
    BRIDGE_CONFIG: string
    SIGNING_KEYS: string
}

const bindings = env as unknown as Bindings
const active = JSON.parse(bindings.SIGNING_KEYS).active as JsonWebKey
const kid = await calculateJwkThumbprint({ kty: active.kty!, crv: active.crv!, x: active.x!, y: active.y! })

// All the probe saw on ESA's context
const context = { waitUntil: () => {} }

type Handler = (request: Request, ...rest: unknown[]) => Promise<Response>
let handler: Handler

// A fresh module for each test, so that no test sees the runtimes another one loaded
beforeEach(async () => {
    vi.resetModules()
    handler = (await import('../src/runtimes/esa')).default.fetch
})

afterEach(() => {
    vi.restoreAllMocks()
})

// The arguments after the request, as ESA would pass them
function via(...rest: unknown[]): Send {
    return (path, init) => handler(new Request(`${BASE}${path}`, init), ...rest)
}

function captureLogs(): () => Record<string, unknown>[] {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    return () => log.mock.calls.map(([text]) => JSON.parse(String(text)) as Record<string, unknown>)
}

function failures(logs: Record<string, unknown>[]): Record<string, unknown>[] {
    return logs.filter((line) => 'event' in line)
}

describe('ESA entry', () => {
    it('serves the runtime loaded from the env given as the third argument', async () => {
        const logs = captureLogs()

        await expectServing(via(context, bindings), kid)
        expect(failures(logs())).toEqual([])
    })

    it('answers in failure mode for an env given as the second argument, as Workers passes it', async () => {
        const logs = captureLogs()

        await expectFailureMode(via(bindings))
        expect(failures(logs())).toEqual([{ event: 'runtime_load_failed', reason: 'missing BRIDGE_CONFIG' }])
    })

    it.each<[string, unknown]>([
        ['undefined', undefined],
        ['null', null],
        ['a string', `BRIDGE_CONFIG=${bindings.BRIDGE_CONFIG}`],
        ['a number', 42],
    ])('answers in failure mode for an env that is %s, rather than throwing', async (_, value) => {
        const logs = captureLogs()

        await expectFailureMode(via(context, value))
        expect(failures(logs())).toEqual([{ event: 'runtime_load_failed', reason: 'missing BRIDGE_CONFIG' }])
    })

    it('reads every env that is not an object as one empty env, loaded once', async () => {
        const logs = captureLogs()

        for (const value of [undefined, null, 'text', 42]) expect((await via(context, value)('/healthz')).status).toBe(503)
        expect(failures(logs())).toEqual([{ event: 'runtime_load_failed', reason: 'missing BRIDGE_CONFIG' }])
    })

    it('loads the runtime once for one env object, logging a bad env once', async () => {
        const logs = captureLogs()
        const bad: Env = { ...bindings, SIGNING_KEYS: undefined }

        for (let attempt = 0; attempt < 2; attempt++) expect((await via(context, bad)('/healthz')).status).toBe(503)
        expect(failures(logs())).toEqual([{ event: 'runtime_load_failed', reason: 'missing SIGNING_KEYS' }])
    })

    it('loads a runtime for each env object', async () => {
        const logs = captureLogs()

        for (const name of ['BRIDGE_CONFIG', 'SIGNING_KEYS'] as const) {
            expect((await via(context, { ...bindings, [name]: undefined })('/healthz')).status).toBe(503)
        }
        expect(failures(logs())).toEqual([
            { event: 'runtime_load_failed', reason: 'missing BRIDGE_CONFIG' },
            { event: 'runtime_load_failed', reason: 'missing SIGNING_KEYS' },
        ])
    })
})
