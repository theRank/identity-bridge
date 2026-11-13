import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { parseConfig } from '../src/config'
import { JwksFetchError } from '../src/idp/fetch'
import { remoteJwks, resetJwksCache } from '../src/idp/jwks'
import { casdoorConfigJson, clerkConfigJson } from './helpers/config'
import { fakeFetch, type Responder } from './helpers/fetch'
import { idpJwks, rsaKeyPair } from './helpers/keys'

const CLERK = parseConfig(clerkConfigJson).idps['clerk-acme']!
const CASDOOR = parseConfig(casdoorConfigJson).idps.casdoor!

const serveEmpty: Responder = () => Response.json({ keys: [] })

async function rejection(pending: Promise<unknown>): Promise<unknown> {
    return pending.then(
        () => undefined,
        (caught: unknown) => caught,
    )
}

beforeEach(() => {
    resetJwksCache()
})

afterEach(() => {
    vi.restoreAllMocks()
})

describe('remoteJwks', () => {
    it('fetches nothing until a key is needed', () => {
        const { fetch, calls } = fakeFetch(serveEmpty)
        remoteJwks(CLERK, fetch)
        expect(calls).toHaveLength(0)
    })

    it('fetches the IdP jwksUri through jwksFetch, with the options jose gives it', async () => {
        const { fetch, calls } = fakeFetch(serveEmpty)
        await remoteJwks(CLERK, fetch).reload()
        expect(calls).toHaveLength(1)
        expect(calls[0]).toMatchObject({ url: 'https://clerk.acme.example/.well-known/jwks.json', method: 'GET', redirect: 'manual' })
        expect(calls[0]!.signal).toBeInstanceOf(AbortSignal)
    })

    it('turns a failed fetch into JwksFetchError rather than a generic jose error', async () => {
        const { fetch } = fakeFetch(() => new Response('<html></html>', { status: 200 }))
        expect(await rejection(remoteJwks(CLERK, fetch).reload())).toBeInstanceOf(JwksFetchError)
    })

    it('gives jose a 5 s timeout', async () => {
        const timeout = vi.spyOn(AbortSignal, 'timeout')
        await remoteJwks(CLERK, fakeFetch(serveEmpty).fetch).reload()
        expect(timeout).toHaveBeenCalledTimes(1)
        expect(timeout).toHaveBeenCalledWith(5000)
    })

    it('keeps one set per IdP id, with the fetch it was created with', async () => {
        const first = fakeFetch(serveEmpty)
        const second = fakeFetch(serveEmpty)
        const set = remoteJwks(CLERK, first.fetch)
        expect(remoteJwks(CLERK, second.fetch)).toBe(set)
        await set.reload()
        expect(first.calls).toHaveLength(1)
        expect(second.calls).toHaveLength(0)
    })

    it('keeps the keys of each IdP apart', async () => {
        const [clerkKey, casdoorKey] = await Promise.all([rsaKeyPair(), rsaKeyPair()])
        const { fetch, calls } = fakeFetch((call) => Response.json(call.url.startsWith('https://clerk.') ? idpJwks(clerkKey) : idpJwks(casdoorKey)))
        const clerk = remoteJwks(CLERK, fetch)
        const casdoor = remoteJwks(CASDOOR, fetch)
        expect(casdoor).not.toBe(clerk)
        await Promise.all([clerk.reload(), casdoor.reload()])
        expect(calls.map((call) => call.url).sort()).toEqual([
            'https://casdoor.example/.well-known/jwks',
            'https://clerk.acme.example/.well-known/jwks.json',
        ])
        expect(clerk.jwks()).toStrictEqual(idpJwks(clerkKey))
        expect(casdoor.jwks()).toStrictEqual(idpJwks(casdoorKey))
    })

    it('waits 30 s after a fetch before a missing key may fetch again', async () => {
        const set = remoteJwks(CLERK, fakeFetch(serveEmpty).fetch)
        await set.reload()
        expect(set.coolingDown).toBe(true)
    })
})

describe('resetJwksCache', () => {
    it('forgets every set, so the next one uses the fetch it is given', async () => {
        const first = fakeFetch(serveEmpty)
        const second = fakeFetch(serveEmpty)
        const set = remoteJwks(CLERK, first.fetch)
        resetJwksCache()
        const next = remoteJwks(CLERK, second.fetch)
        expect(next).not.toBe(set)
        await next.reload()
        expect(first.calls).toHaveLength(0)
        expect(second.calls).toHaveLength(1)
    })

    it('sets the cooldown of the sets created after it, until the next reset', async () => {
        resetJwksCache({ cooldownDuration: 0 })
        const immediate = remoteJwks(CLERK, fakeFetch(serveEmpty).fetch)
        await immediate.reload()
        expect(immediate.coolingDown).toBe(false)

        resetJwksCache()
        const standard = remoteJwks(CLERK, fakeFetch(serveEmpty).fetch)
        await standard.reload()
        expect(standard.coolingDown).toBe(true)
    })
})
