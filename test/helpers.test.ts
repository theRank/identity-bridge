import { createLocalJWKSet, importJWK, jwtVerify, SignJWT } from 'jose'
import { describe, expect, it } from 'vitest'
import { casdoorConfig, casdoorConfigJson, clerkConfig, clerkConfigJson } from './helpers/config'
import { fakeDeps, START_MS } from './helpers/deps'
import { fakeFetch, hang } from './helpers/fetch'
import { bridgeSigningKeys, ecKeyPair, idpJwks, rsaKeyPair, type IdpKeyPair } from './helpers/keys'

async function signAndVerify(pair: IdpKeyPair) {
    const token = await new SignJWT({ sub: 'user' }).setProtectedHeader({ alg: pair.alg, kid: pair.kid }).sign(pair.privateKey)
    return jwtVerify(token, createLocalJWKSet(idpJwks(pair)))
}

describe('bridgeSigningKeys', () => {
    it('gives a SIGNING_KEYS value with an EC P-256 private key and public retired keys', async () => {
        const keys = await bridgeSigningKeys(2)
        expect(JSON.parse(keys.json)).toEqual({ active: keys.active, retired: keys.retired })
        expect(Object.keys(keys.active).sort()).toEqual(['crv', 'd', 'kty', 'x', 'y'])
        expect(keys.active).toMatchObject({ kty: 'EC', crv: 'P-256' })
        expect(keys.retired).toHaveLength(2)
        for (const retired of keys.retired) {
            expect(Object.keys(retired).sort()).toEqual(['crv', 'kty', 'x', 'y'])
            expect(retired.x).not.toBe(keys.active.x)
        }
    })

    it('has an active key that jose imports for ES256', async () => {
        const { active } = await bridgeSigningKeys()
        const key = await importJWK(active, 'ES256')
        expect(key).toBeInstanceOf(CryptoKey)
    })

    it('generates different keys on every call', async () => {
        const [a, b] = await Promise.all([bridgeSigningKeys(), bridgeSigningKeys()])
        expect(a.active.d).not.toBe(b.active.d)
    })
})

describe('IdP key pairs', () => {
    it.each(['RS256', 'RS384', 'RS512', 'PS256'] as const)('signs %s tokens that verify against the JWKS', async (alg) => {
        const pair = await rsaKeyPair({ alg, kid: `rsa-${alg}` })
        expect(pair.publicJwk).toMatchObject({ kty: 'RSA', kid: `rsa-${alg}`, alg, use: 'sig' })
        expect(pair.publicJwk).not.toHaveProperty('d')
        const { protectedHeader } = await signAndVerify(pair)
        expect(protectedHeader).toEqual({ alg, kid: `rsa-${alg}` })
    })

    it.each(['ES256', 'ES384'] as const)('signs %s tokens that verify against the JWKS', async (alg) => {
        const pair = await ecKeyPair({ alg })
        expect(pair.publicJwk).toMatchObject({ kty: 'EC', crv: alg === 'ES256' ? 'P-256' : 'P-384', alg, use: 'sig' })
        expect(pair.publicJwk).not.toHaveProperty('d')
        await signAndVerify(pair)
    })

    it('makes a short RSA key on request', async () => {
        const pair = await rsaKeyPair({ modulusLength: 1024 })
        const modulus = Uint8Array.from(atob(pair.publicJwk.n!.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
        expect(modulus.byteLength).toBe(128)
    })

    it('gives each pair its own kid by default', async () => {
        const [a, b] = await Promise.all([ecKeyPair(), ecKeyPair()])
        expect(a.kid).not.toBe(b.kid)
        expect(idpJwks(a, b).keys.map((key) => key.kid)).toEqual([a.kid, b.kid])
    })
})

describe('fakeFetch', () => {
    it('records each call and answers through the responder', async () => {
        const { fetch, calls } = fakeFetch(async (call) => Response.json({ echoed: call.body }, { status: 201 }))
        const response = await fetch('https://idp.example/events', {
            method: 'POST',
            headers: { 'content-type': 'application/secevent+jwt' },
            body: 'jwt',
            redirect: 'manual',
        })
        expect(response.status).toBe(201)
        expect(await response.json()).toEqual({ echoed: 'jwt' })
        expect(calls).toHaveLength(1)
        expect(calls[0]).toMatchObject({ url: 'https://idp.example/events', method: 'POST', body: 'jwt', redirect: 'manual' })
        expect(calls[0]!.headers.get('content-type')).toBe('application/secevent+jwt')
    })

    it('accepts a Request', async () => {
        const { fetch, calls } = fakeFetch(() => new Response(null, { status: 204 }))
        await fetch(new Request('https://idp.example/jwks', { headers: { accept: 'application/json' } }))
        expect(calls[0]).toMatchObject({ url: 'https://idp.example/jwks', method: 'GET', body: '' })
    })

    it('rejects with the signal reason when the signal aborts', async () => {
        const { fetch, calls } = fakeFetch(hang)
        const controller = new AbortController()
        const pending = fetch('https://idp.example/jwks', { signal: controller.signal })
        controller.abort(new DOMException('timed out', 'TimeoutError'))
        await expect(pending).rejects.toMatchObject({ name: 'TimeoutError' })
        expect(calls).toHaveLength(1)
    })

    it('honours AbortSignal.timeout', async () => {
        const { fetch } = fakeFetch(hang)
        await expect(fetch('https://idp.example/jwks', { signal: AbortSignal.timeout(10) })).rejects.toMatchObject({ name: 'TimeoutError' })
    })

    it('rejects at once for a signal that already aborted, and still records the call', async () => {
        let answered = false
        const { fetch, calls } = fakeFetch(() => {
            answered = true
            return new Response(null)
        })
        await expect(fetch('https://idp.example/jwks', { signal: AbortSignal.abort() })).rejects.toMatchObject({ name: 'AbortError' })
        expect(answered).toBe(false)
        expect(calls).toHaveLength(1)
    })

    it('keeps waiting through an abort when told to ignore the signal', async () => {
        const { fetch } = fakeFetch(hang, { ignoreSignal: true })
        const controller = new AbortController()
        const pending = fetch('https://idp.example/jwks', { signal: controller.signal })
        controller.abort()
        const timer = new Promise((resolve) => setTimeout(() => resolve('still waiting'), 20))
        expect(await Promise.race([pending, timer])).toBe('still waiting')
    })
})

describe('configuration documents', () => {
    it('gives a fresh object on every call', () => {
        const changed = clerkConfig()
        changed.products.acme.allowedOrigins.push('https://other.example')
        expect(clerkConfig().products.acme.allowedOrigins).toEqual(['https://acme.example'])
    })

    it('serializes the same documents as JSON', () => {
        expect(JSON.parse(clerkConfigJson)).toEqual(clerkConfig())
        expect(JSON.parse(casdoorConfigJson)).toEqual(casdoorConfig())
    })

    it('uses only reserved example hosts', () => {
        const hosts = [clerkConfigJson, casdoorConfigJson].flatMap((json) => [...json.matchAll(/https:\/\/([^/"]+)/g)].map((m) => m[1]!))
        expect(hosts.length).toBeGreaterThan(0)
        for (const host of hosts) expect(host).toMatch(/(^|\.)example$/)
    })
})

describe('fakeDeps', () => {
    it('moves the clock only when told to', () => {
        const { deps, advance } = fakeDeps()
        expect(deps.now()).toBe(START_MS)
        advance(1500)
        expect(deps.now()).toBe(START_MS + 1500)
    })

    it('gives sequential UUIDs in the canonical v4 shape', () => {
        const { deps } = fakeDeps()
        const ids = [deps.randomUUID(), deps.randomUUID()]
        expect(ids).toEqual(['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002'])
        for (const id of ids) expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    })

    it('records log lines', () => {
        const { deps, logs } = fakeDeps()
        deps.log({ route: 'health', status: 200, ms: 1, outcome: 'ok' })
        expect(logs).toEqual([{ route: 'health', status: 200, ms: 1, outcome: 'ok' }])
    })

    it('rejects fetches unless one is given', async () => {
        await expect(fakeDeps().deps.fetch('https://idp.example/jwks')).rejects.toThrow('unexpected fetch')
        const { fetch } = fakeFetch(() => new Response('ok'))
        expect(await (await fakeDeps({ fetch }).deps.fetch('https://idp.example/jwks')).text()).toBe('ok')
    })
})
