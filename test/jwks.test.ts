import { beforeAll, describe, expect, it } from 'vitest'
import { handle } from '../src/app'
import { parseConfig } from '../src/config'
import { importSigningKeys } from '../src/keys'
import type { PublicJwk, Runtime, SigningKeys } from '../src/types'
import { clerkConfigJson } from './helpers/config'
import { fakeDeps } from './helpers/deps'
import { bridgeSigningKeys, type BridgeKeys } from './helpers/keys'

const JWKS_URL = 'https://id.acme.example/.well-known/jwks.json'

let generated: BridgeKeys
let keys: SigningKeys

beforeAll(async () => {
    generated = await bridgeSigningKeys(2)
    keys = await importSigningKeys(generated.json)
})

function runtime(signingKeys: SigningKeys = keys): Runtime {
    return {
        config: parseConfig(clerkConfigJson),
        keys: signingKeys,
        webhookSecret: () => {
            throw new Error('not read by this route')
        },
    }
}

async function getJwks(loaded: Runtime = runtime()) {
    const { deps, logs } = fakeDeps()
    const response = await handle(new Request(JWKS_URL), loaded, deps)
    return { response, logs }
}

describe('GET /.well-known/jwks.json', () => {
    it('answers 200 JSON, cacheable for 300 s', async () => {
        const { response, logs } = await getJwks()
        expect(response.status).toBe(200)
        expect(response.headers.get('content-type')).toBe('application/json')
        expect(response.headers.get('cache-control')).toBe('public, max-age=300')
        expect(logs).toEqual([{ route: 'jwks', status: 200, ms: 0, outcome: 'ok' }])
    })

    it('publishes the active key first, then the retired keys in order', async () => {
        const { response } = await getJwks()
        const { keys: published } = (await response.json()) as { keys: PublicJwk[] }
        expect(published.map((key) => key.kid)).toEqual(keys.jwks.keys.map((key) => key.kid))
        expect(published[0]!.kid).toBe(keys.kid)
        expect(published.map(({ x, y }) => ({ x, y }))).toEqual([generated.active, ...generated.retired].map(({ x, y }) => ({ x, y })))
    })

    it('gives each key exactly kty, crv, x, y, kid, alg and use', async () => {
        const { response } = await getJwks()
        const body = (await response.json()) as { keys: Record<string, unknown>[] }
        expect(Object.keys(body)).toEqual(['keys'])
        expect(body.keys).toHaveLength(3)
        for (const key of body.keys) {
            expect(Object.keys(key).sort()).toEqual(['alg', 'crv', 'kid', 'kty', 'use', 'x', 'y'])
            expect(key).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' })
        }
    })

    // importSigningKeys never puts a private member in the key set, so one is planted to show the route drops it
    it('never publishes the private key or any other member a key object holds', async () => {
        const [active] = keys.jwks.keys
        const leaky = { ...active!, d: generated.active.d, ext: true } as PublicJwk
        const { response } = await getJwks(runtime({ ...keys, jwks: { keys: [leaky] } }))
        const text = await response.text()
        expect(text).not.toContain('"d"')
        expect(text).not.toContain(generated.active.d)
        expect(JSON.parse(text)).toStrictEqual({ keys: [active] })
    })
})
