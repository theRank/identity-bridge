import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { handle } from '../src/app'
import { parseConfig } from '../src/config'
import { importSigningKeys } from '../src/keys'
import type { Runtime } from '../src/types'
import { clerkConfigJson } from './helpers/config'
import { fakeDeps } from './helpers/deps'
import { bridgeSigningKeys } from './helpers/keys'

const HEALTH_URL = 'https://id.acme.example/healthz'

let runtime: Runtime

beforeAll(async () => {
    runtime = {
        config: parseConfig(clerkConfigJson),
        keys: await importSigningKeys((await bridgeSigningKeys()).json),
        webhookSecret: () => {
            throw new Error('not read by this route')
        },
    }
})

afterEach(() => {
    vi.restoreAllMocks()
})

// The self-test result is memoized per module instance, so a failing one needs a module graph of its own
async function freshHandle(): Promise<typeof handle> {
    vi.resetModules()
    return (await import('../src/app')).handle
}

function algorithmName(algorithm: string | { name: string }): string {
    return typeof algorithm === 'string' ? algorithm : algorithm.name
}

describe('GET /healthz', () => {
    it('answers 200 ok when the self-test passes', async () => {
        const { deps, logs } = fakeDeps()
        const response = await handle(new Request(HEALTH_URL), runtime, deps)
        expect(response.status).toBe(200)
        expect(response.headers.get('content-type')).toBe('application/json')
        expect(await response.json()).toStrictEqual({ status: 'ok' })
        expect(logs).toEqual([{ route: 'health', status: 200, ms: 0, outcome: 'ok' }])
    })

    it('answers 503 unavailable, without naming what failed, when the self-test fails', async () => {
        const digest = crypto.subtle.digest.bind(crypto.subtle)
        const spy = vi
            .spyOn(crypto.subtle, 'digest')
            .mockImplementation(async (algorithm, data) => (algorithmName(algorithm) === 'SHA-1' ? new ArrayBuffer(20) : digest(algorithm, data)))
        const { deps, logs } = fakeDeps()
        const response = await (await freshHandle())(new Request(HEALTH_URL), runtime, deps)
        // The forced wrong digest is what the self-test saw
        expect(spy.mock.calls.map(([algorithm]) => algorithmName(algorithm))).toContain('SHA-1')
        expect(response.status).toBe(503)
        expect(response.headers.get('content-type')).toBe('application/json')
        expect(await response.json()).toStrictEqual({ status: 'unavailable' })
        expect(logs).toEqual([{ route: 'health', status: 503, ms: 0, outcome: 'error' }])
    })
})
