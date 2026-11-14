import { decodeJwt, decodeProtectedHeader } from 'jose'
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Responder } from '../../../test/helpers/fetch'
import { idpJwks } from '../../../test/helpers/keys'
import { BridgeError, createBridgeClient, type Transport } from '../src/index'
import { BRIDGE_URL, bridge, FORM, generateKeys, rejection, tick, until, type Bridge, type BridgeOptions, type Keys } from './bridge'

const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
const JWT_TYPE = 'urn:ietf:params:oauth:token-type:jwt'
const TOKEN_URL = `${BRIDGE_URL.clerk}/token`

let keys: Keys

beforeAll(async () => {
    keys = await generateKeys()
})

afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
})

function deferred() {
    let release: () => void = () => {}
    const promise = new Promise<void>((resolve) => (release = resolve))
    return { promise, release }
}

interface Setup {
    bridge: Bridge
    client: ReturnType<typeof createBridgeClient>
    getIdpToken: ReturnType<typeof vi.fn<() => Promise<string>>>
}

interface SetupOptions extends BridgeOptions {
    refreshBeforeSeconds?: number
    getIdpToken?: () => Promise<string>
    transport?: (bridge: Bridge) => Transport
    // The client's clock against the bridge's, in ms
    skew?: number
}

// A client of the real bridge sharing its clock, so the bridge accepts each fresh IdP token
function setup(options: SetupOptions = {}): Setup {
    const real = bridge(keys, options)
    const getIdpToken = vi.fn(options.getIdpToken ?? real.idpToken)
    const client = createBridgeClient({
        url: BRIDGE_URL.clerk,
        audience: 'acme',
        getIdpToken,
        transport: options.transport?.(real) ?? real.transport,
        now: () => real.now() + (options.skew ?? 0),
        ...(options.refreshBeforeSeconds === undefined ? {} : { refreshBeforeSeconds: options.refreshBeforeSeconds }),
    })
    return { bridge: real, client, getIdpToken }
}

function formOf(fields: Record<string, string>): string {
    return new URLSearchParams(fields).toString()
}

async function bridgeError(pending: Promise<unknown>): Promise<BridgeError> {
    const error = await rejection(pending)
    expect(error).toBeInstanceOf(BridgeError)
    return error as BridgeError
}

// The IdP's JWKS serves the bridge's first `working` fetches, fails the next `failures`, so the bridge answers 503
// temporarily_unavailable, and serves again after that
function idpDown(failures: number, working = 0): Responder {
    let calls = 0
    return () => {
        calls++
        const failing = calls > working && calls <= working + failures
        return failing ? new Response(null, { status: 500 }) : Response.json(idpJwks(keys.clerk))
    }
}

// With fake timers: once the last answer is in and the client sleeps, the next request goes out exactly `ms` later
async function nextRequestAfter(ms: number, requests: unknown[], settled: () => boolean): Promise<void> {
    await until(() => settled() && vi.getTimerCount() === 1)
    const sent = requests.length
    await vi.advanceTimersByTimeAsync(ms - 1)
    await tick()
    expect(requests).toHaveLength(sent)
    await vi.advanceTimersByTimeAsync(1)
    await until(() => requests.length === sent + 1)
}

// Drives a failing exchange through its two retries; `settled` holds once every request sent has its answer
async function throughRetries(requests: unknown[], settled: () => boolean = () => true): Promise<void> {
    await nextRequestAfter(250, requests, settled)
    await nextRequestAfter(1000, requests, settled)
}

// Sends through the real bridge, and finds no answer while the outage is on
function flaky(outage: { on: boolean }, attempts: unknown[]): (real: Bridge) => Transport {
    return (real) => async (request) => {
        attempts.push(request)
        if (outage.on) throw new TypeError('Failed to fetch')
        return real.transport(request)
    }
}

describe('createBridgeClient', () => {
    describe('exchange', () => {
        it('exchanges the IdP token at the bridge for an access token of the product', async () => {
            const { bridge, client, getIdpToken } = setup()
            const token = await client.getToken()
            expect(decodeProtectedHeader(token)).toMatchObject({ alg: 'ES256', typ: 'at+jwt' })
            expect(decodeJwt(token)).toMatchObject({ iss: BRIDGE_URL.clerk, aud: 'acme', client_id: 'acme' })
            expect(bridge.answers).toEqual([{ status: 200, body: expect.objectContaining({ access_token: token, expires_in: 900 }) }])
            expect(bridge.requests.map((request) => request.url)).toEqual([TOKEN_URL])
            expect(getIdpToken).toHaveBeenCalledTimes(1)
        })

        it('sends the token exchange form, encoded as URLSearchParams encodes it', async () => {
            const { bridge, client, getIdpToken } = setup()
            await client.getToken()
            const subjectToken = await getIdpToken.mock.results[0]!.value
            const fields = { grant_type: TOKEN_EXCHANGE, subject_token: subjectToken, subject_token_type: JWT_TYPE, audience: 'acme' }
            expect(bridge.requests[0]!.body).toBe(formOf(fields))
        })

        it('encodes every character as URLSearchParams does, including spaces and reserved characters', async () => {
            const awkward = " a+b&c=d%e!f'g(h)i~j*k-l.m_n/o?p#q😀é \n"
            const { bridge } = setup()
            const client = createBridgeClient({ url: BRIDGE_URL.clerk, audience: `acme ${awkward}`, getIdpToken: async () => awkward, transport: bridge.transport })
            await rejection(client.getToken())
            const fields = { grant_type: TOKEN_EXCHANGE, subject_token: awkward, subject_token_type: JWT_TYPE, audience: `acme ${awkward}` }
            expect(bridge.requests[0]!.body).toBe(formOf(fields))
        })
    })

    describe('cache', () => {
        it('returns the cached token without exchanging again', async () => {
            const { bridge, client, getIdpToken } = setup()
            const first = await client.getToken()
            bridge.advance(60_000)
            expect(await client.getToken()).toBe(first)
            expect(bridge.requests).toHaveLength(1)
            expect(getIdpToken).toHaveBeenCalledTimes(1)
        })

        it('exchanges again once 60 s or less of the lifetime remain', async () => {
            const { bridge, client } = setup()
            const first = await client.getToken()
            bridge.advance(839_999)
            expect(await client.getToken()).toBe(first)
            bridge.advance(1)
            const second = await client.getToken()
            expect(second).not.toBe(first)
            expect(bridge.requests).toHaveLength(2)
            expect(await client.getToken()).toBe(second)
        })

        it('with a 60 s lifetime, exchanges again after 30 s rather than on every call', async () => {
            const { bridge, client } = setup({ tokenTtlSeconds: 60 })
            const first = await client.getToken()
            bridge.advance(29_999)
            expect(await client.getToken()).toBe(first)
            bridge.advance(1)
            expect(await client.getToken()).not.toBe(first)
            expect(bridge.requests).toHaveLength(2)
        })

        it('refreshes refreshBeforeSeconds before expiry', async () => {
            const { bridge, client } = setup({ refreshBeforeSeconds: 300 })
            const first = await client.getToken()
            bridge.advance(599_999)
            expect(await client.getToken()).toBe(first)
            bridge.advance(1)
            expect(await client.getToken()).not.toBe(first)
        })

        it('measures the lifetime from when the answer arrives, by its own clock, whatever the token says', async () => {
            // The client's clock is a day ahead, and the bridge takes 10 s to answer
            const { bridge, client } = setup({
                skew: 86_400_000,
                transport: (real) => async (request) => {
                    const answer = await real.transport(request)
                    real.advance(10_000)
                    return answer
                },
            })
            const first = await client.getToken()
            bridge.advance(839_999)
            expect(await client.getToken()).toBe(first)
            bridge.advance(1)
            expect(await client.getToken()).not.toBe(first)
        })

        it('keeps the token in memory only: it touches no storage and logs nothing', async () => {
            const touched: string[] = []
            // Records any read or write of a storage global, document.cookie included
            const watched = (name: string) =>
                new Proxy(
                    {},
                    {
                        get(_, key) {
                            touched.push(`${name}.${String(key)}`)
                            return () => {}
                        },
                        set(_, key) {
                            touched.push(`${name}.${String(key)} =`)
                            return true
                        },
                    },
                )
            for (const name of ['localStorage', 'sessionStorage', 'indexedDB', 'caches', 'document']) vi.stubGlobal(name, watched(name))
            const logged = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) => vi.spyOn(console, method))
            const { bridge, client } = setup()
            await client.getToken()
            bridge.advance(840_000)
            await client.getToken()
            client.clear()
            await client.getToken()
            expect(bridge.requests).toHaveLength(3)
            expect(touched).toEqual([])
            for (const spy of logged) expect(spy).not.toHaveBeenCalled()
        })
    })

    describe('single flight', () => {
        it('makes one exchange for ten concurrent calls', async () => {
            const { bridge, client, getIdpToken } = setup()
            const tokens = await Promise.all(Array.from({ length: 10 }, () => client.getToken()))
            expect(new Set(tokens).size).toBe(1)
            expect(bridge.requests).toHaveLength(1)
            expect(getIdpToken).toHaveBeenCalledTimes(1)
        })

        it('shares the refresh between callers once the token is due', async () => {
            const { bridge, client } = setup()
            const first = await client.getToken()
            bridge.advance(840_000)
            const tokens = await Promise.all(Array.from({ length: 10 }, () => client.getToken()))
            expect(new Set(tokens).size).toBe(1)
            expect(tokens[0]).not.toBe(first)
            expect(bridge.requests).toHaveLength(2)
        })
    })

    describe('errors', () => {
        it('throws a 400 as BridgeError with the OAuth error, without retrying', async () => {
            const { bridge, client } = setup({ getIdpToken: async () => 'not-a-jwt' })
            const error = await bridgeError(client.getToken())
            expect(error).toMatchObject({ name: 'BridgeError', status: 400, error: 'invalid_request' })
            expect(bridge.requests).toHaveLength(1)
        })

        it('does not expose error_description', async () => {
            const { bridge, client } = setup({ getIdpToken: async () => 'not-a-jwt' })
            const error = await bridgeError(client.getToken())
            const description = (bridge.answers[0]!.body as Record<string, unknown>).error_description as string
            expect(description).toBe('The subject token is not acceptable.')
            expect(error).not.toHaveProperty('error_description')
            expect(error.message).not.toContain(description)
            expect(JSON.stringify(error)).not.toContain(description)
        })

        it('throws an unknown audience as BridgeError invalid_target', async () => {
            const { bridge } = setup()
            const client = createBridgeClient({ url: BRIDGE_URL.clerk, audience: 'globex', getIdpToken: bridge.idpToken, transport: bridge.transport })
            expect(await bridgeError(client.getToken())).toMatchObject({ status: 400, error: 'invalid_target' })
        })

        it('does not cache a failed exchange: the next call exchanges again', async () => {
            const { bridge, client, getIdpToken } = setup()
            getIdpToken.mockResolvedValueOnce('not-a-jwt')
            await bridgeError(client.getToken())
            const token = await client.getToken()
            expect(decodeJwt(token).aud).toBe('acme')
            expect(bridge.requests).toHaveLength(2)
            expect(getIdpToken).toHaveBeenCalledTimes(2)
        })

        it('passes a failure of getIdpToken on unchanged, without calling the bridge, and does not cache it', async () => {
            const { bridge, client, getIdpToken } = setup()
            const failure = new Error('signed out')
            getIdpToken.mockRejectedValueOnce(failure)
            expect(await rejection(client.getToken())).toBe(failure)
            expect(bridge.requests).toHaveLength(0)
            await client.getToken()
            expect(bridge.requests).toHaveLength(1)
        })

        it.each([
            ['a 200 without access_token', { status: 200, body: { expires_in: 900 } }, 200],
            ['a 200 without expires_in', { status: 200, body: { access_token: 'token' } }, 200],
            ['a 200 with a zero expires_in', { status: 200, body: { access_token: 'token', expires_in: 0 } }, 200],
            ['a 200 with an empty access_token', { status: 200, body: { access_token: '', expires_in: 900 } }, 200],
            ['a 200 whose body is not JSON', { status: 200, body: undefined }, 200],
            ['an error without an OAuth error', { status: 502, body: '<html>Bad gateway</html>' }, 502],
            ['an error whose error is not a string', { status: 400, body: { error: 42 } }, 400],
            ['a 503 that is not temporarily_unavailable', { status: 503, body: { error: 'overloaded' } }, 503],
        ])('throws %s as BridgeError bad_response or its error, without retrying', async (_, answer, status) => {
            const transport = vi.fn(async () => answer)
            const { client } = setup({ transport: () => transport })
            const error = await bridgeError(client.getToken())
            expect(error.status).toBe(status)
            expect(error.error).toBe(status === 503 ? 'overloaded' : 'bad_response')
            expect(transport).toHaveBeenCalledTimes(1)
        })

        it('throws server_error from the bridge without retrying', async () => {
            const transport = vi.fn(async () => ({ status: 500, body: { error: 'server_error', error_description: 'The service failed.' } }))
            const { client } = setup({ transport: () => transport })
            expect(await bridgeError(client.getToken())).toMatchObject({ status: 500, error: 'server_error' })
            expect(transport).toHaveBeenCalledTimes(1)
        })

        it('rejects a negative refreshBeforeSeconds', () => {
            const options = { url: BRIDGE_URL.clerk, audience: 'acme', getIdpToken: async () => 'token' }
            expect(() => createBridgeClient({ ...options, refreshBeforeSeconds: -1 })).toThrow(RangeError)
            expect(() => createBridgeClient({ ...options, refreshBeforeSeconds: Number.NaN })).toThrow(RangeError)
            expect(() => createBridgeClient({ ...options, refreshBeforeSeconds: 0 })).not.toThrow()
        })
    })

    describe('retries', () => {
        beforeEach(() => {
            vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
        })

        afterEach(() => {
            vi.useRealTimers()
        })

        it('retries a 503 temporarily_unavailable after 250 ms with the same IdP token, then succeeds', async () => {
            const { bridge, client, getIdpToken } = setup({ respond: idpDown(1) })
            const pending = client.getToken()
            await nextRequestAfter(250, bridge.requests, () => bridge.answers.length === 1)
            const token = await pending
            expect(bridge.answers.map((answer) => answer.status)).toEqual([503, 200])
            expect(bridge.answers[0]!.body).toMatchObject({ error: 'temporarily_unavailable' })
            expect(decodeJwt(token).aud).toBe('acme')
            expect(getIdpToken).toHaveBeenCalledTimes(1)
            expect(bridge.requests[1]).toStrictEqual(bridge.requests[0])
        })

        it('retries twice, after 250 ms and then 1 s, and then throws the 503 as BridgeError', async () => {
            const { bridge, client, getIdpToken } = setup({ respond: idpDown(Infinity) })
            const pending = rejection(client.getToken())
            await nextRequestAfter(250, bridge.requests, () => bridge.answers.length === 1)
            await nextRequestAfter(1000, bridge.requests, () => bridge.answers.length === 2)
            const error = await pending
            expect(error).toBeInstanceOf(BridgeError)
            expect(error).toMatchObject({ status: 503, error: 'temporarily_unavailable' })
            expect(bridge.requests).toHaveLength(3)
            expect(new Set(bridge.requests.map((request) => request.body)).size).toBe(1)
            expect(getIdpToken).toHaveBeenCalledTimes(1)
            expect(vi.getTimerCount()).toBe(0)
        })

        it('retries a rejected transport the same way, then throws BridgeError network with status 0', async () => {
            const reason = new Error('request failed: subject_token=secret-marker')
            const transport = vi.fn(async () => {
                throw reason
            })
            const { client, getIdpToken } = setup({ transport: () => transport })
            const pending = rejection(client.getToken())
            await nextRequestAfter(250, transport.mock.calls, () => true)
            await nextRequestAfter(1000, transport.mock.calls, () => true)
            const error = await pending
            expect(error).toBeInstanceOf(BridgeError)
            expect(error).toMatchObject({ status: 0, error: 'network' })
            expect(error).not.toHaveProperty('cause')
            expect(String((error as Error).message)).not.toContain('secret-marker')
            expect(transport).toHaveBeenCalledTimes(3)
            expect(getIdpToken).toHaveBeenCalledTimes(1)
        })

        it('succeeds when the transport recovers on a retry', async () => {
            let calls = 0
            const { bridge, client } = setup({
                transport: (real) => async (request) => {
                    if (++calls === 1) throw new TypeError('Failed to fetch')
                    return real.transport(request)
                },
            })
            const pending = client.getToken()
            await until(() => vi.getTimerCount() === 1)
            await vi.advanceTimersByTimeAsync(250)
            expect(decodeJwt(await pending).aud).toBe('acme')
            expect(bridge.requests).toHaveLength(1)
        })

        it('shares the retried exchange between concurrent callers', async () => {
            const { bridge, client } = setup({ respond: idpDown(1) })
            const pending = Promise.all(Array.from({ length: 10 }, () => client.getToken()))
            await nextRequestAfter(250, bridge.requests, () => bridge.answers.length === 1)
            expect(new Set(await pending).size).toBe(1)
            expect(bridge.requests).toHaveLength(2)
        })
    })

    describe('when a refresh cannot reach the bridge', () => {
        beforeEach(() => {
            vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] })
        })

        afterEach(() => {
            vi.useRealTimers()
        })

        // A client whose first token was issued, now inside its refresh window, with the bridge out of reach
        async function refreshing(advance = 840_000) {
            const outage = { on: false }
            const attempts: unknown[] = []
            const ready = setup({ transport: flaky(outage, attempts) })
            const first = await ready.client.getToken()
            ready.bridge.advance(advance)
            outage.on = true
            return { ...ready, first, outage, attempts }
        }

        it('returns the cached token while it has not expired, and tries to refresh again on the next call', async () => {
            const { client, first, outage, attempts } = await refreshing()
            const pending = client.getToken()
            await throughRetries(attempts)
            expect(await pending).toBe(first)
            expect(attempts).toHaveLength(4)
            outage.on = false
            const second = await client.getToken()
            expect(second).not.toBe(first)
            expect(attempts).toHaveLength(5)
            expect(await client.getToken()).toBe(second)
        })

        it('gives the cached token to every caller of the failed refresh', async () => {
            const { client, first, attempts } = await refreshing()
            const pending = Promise.all(Array.from({ length: 5 }, () => client.getToken()))
            await throughRetries(attempts)
            expect(await pending).toEqual(Array(5).fill(first))
            expect(attempts).toHaveLength(4)
        })

        it('returns the cached token while the bridge stays temporarily_unavailable', async () => {
            const { bridge, client } = setup({ respond: idpDown(Infinity, 1) })
            const first = await client.getToken()
            // Past the bridge's cache of the IdP's keys, so it fetches them again, and fails
            vi.setSystemTime(Date.now() + 11 * 60_000)
            bridge.advance(840_000)
            const pending = client.getToken()
            await throughRetries(bridge.requests, () => bridge.answers.length === bridge.requests.length)
            expect(await pending).toBe(first)
            expect(bridge.answers.map((answer) => answer.status)).toEqual([200, 503, 503, 503])
        })

        it('returns the cached token up to the last millisecond of its lifetime', async () => {
            const { client, first, attempts } = await refreshing(899_999)
            const pending = client.getToken()
            await throughRetries(attempts)
            expect(await pending).toBe(first)
        })

        it('throws once the cached token has expired', async () => {
            const { client, attempts } = await refreshing(900_000)
            const pending = bridgeError(client.getToken())
            await throughRetries(attempts)
            expect(await pending).toMatchObject({ status: 0, error: 'network' })
        })

        it('throws any other failure of the bridge, even while the cached token is valid', async () => {
            const { bridge, client, getIdpToken } = setup()
            await client.getToken()
            bridge.advance(840_000)
            getIdpToken.mockResolvedValueOnce('not-a-jwt')
            expect(await bridgeError(client.getToken())).toMatchObject({ status: 400, error: 'invalid_request' })
        })

        it('passes on a failure of getIdpToken, even one that says network', async () => {
            const { bridge, client, getIdpToken } = setup()
            await client.getToken()
            bridge.advance(840_000)
            const failure = new BridgeError(0, 'network')
            getIdpToken.mockRejectedValueOnce(failure)
            expect(await rejection(client.getToken())).toBe(failure)
        })

        it('has no token to fall back to after clear()', async () => {
            const { client, attempts } = await refreshing()
            client.clear()
            const pending = bridgeError(client.getToken())
            await throughRetries(attempts)
            expect(await pending).toMatchObject({ error: 'network' })
        })

        it('does not fall back once clear() is called during the failing refresh', async () => {
            const { client, attempts } = await refreshing()
            const pending = bridgeError(client.getToken())
            await until(() => vi.getTimerCount() === 1)
            client.clear()
            await vi.advanceTimersByTimeAsync(250)
            await until(() => attempts.length === 3 && vi.getTimerCount() === 1)
            await vi.advanceTimersByTimeAsync(1000)
            expect(await pending).toMatchObject({ error: 'network' })
            expect(attempts).toHaveLength(4)
        })
    })

    describe('clear', () => {
        it('drops the cached token, so the next call exchanges again', async () => {
            const { bridge, client } = setup()
            const first = await client.getToken()
            client.clear()
            expect(await client.getToken()).not.toBe(first)
            expect(bridge.requests).toHaveLength(2)
        })

        it('lets an exchange in flight resolve for its callers without caching its token', async () => {
            let release: () => void = () => {}
            const gate = new Promise<void>((resolve) => (release = resolve))
            const { bridge, client } = setup({
                transport: (real) => async (request) => {
                    const answer = await real.transport(request)
                    await gate
                    return answer
                },
            })
            const pending = Promise.all([client.getToken(), client.getToken()])
            await until(() => bridge.answers.length === 1)
            client.clear()
            release()
            const [first, second] = await pending
            expect(first).toBe(second)
            expect(decodeJwt(first).aud).toBe('acme')
            expect(await client.getToken()).not.toBe(first)
            expect(bridge.requests).toHaveLength(2)
        })

        it('starts a new exchange for a call made after clear(), and caches that one', async () => {
            let release: () => void = () => {}
            const gate = new Promise<void>((resolve) => (release = resolve))
            const { bridge, client } = setup({
                transport: (real) => async (request) => {
                    const answer = await real.transport(request)
                    if (real.answers.length === 1) await gate
                    return answer
                },
            })
            const before = client.getToken()
            await until(() => bridge.answers.length === 1)
            client.clear()
            const after = await client.getToken()
            release()
            expect(await before).not.toBe(after)
            expect(await client.getToken()).toBe(after)
            expect(bridge.requests).toHaveLength(2)
        })

        it('does not let a cleared exchange that fails drop the exchange started after clear()', async () => {
            const gates = [deferred(), deferred()]
            const { bridge, client, getIdpToken } = setup({
                transport: (real) => async (request) => {
                    const gate = gates[real.requests.length]!
                    const answer = await real.transport(request)
                    await gate.promise
                    return answer
                },
            })
            getIdpToken.mockResolvedValueOnce('not-a-jwt')
            const before = bridgeError(client.getToken())
            await until(() => bridge.answers.length === 1)
            client.clear()
            const after = client.getToken()
            await until(() => bridge.answers.length === 2)
            gates[0]!.release()
            expect(await before).toMatchObject({ status: 400, error: 'invalid_request' })
            // Made while the exchange started after clear() is still in flight: it joins that exchange
            const third = client.getToken()
            gates[1]!.release()
            expect(await third).toBe(await after)
            expect(bridge.requests).toHaveLength(2)
            expect(await client.getToken()).toBe(await after)
        })

        describe('during a retry', () => {
            beforeEach(() => {
                vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
            })

            afterEach(() => {
                vi.useRealTimers()
            })

            it('starts a new exchange at once, and the sleeping one resolves for its callers without being cached', async () => {
                let calls = 0
                const { bridge, client } = setup({
                    transport: (real) => async (request) => {
                        if (++calls === 1) throw new TypeError('Failed to fetch')
                        return real.transport(request)
                    },
                })
                const before = client.getToken()
                await until(() => vi.getTimerCount() === 1)
                client.clear()
                const after = await client.getToken()
                await vi.advanceTimersByTimeAsync(250)
                const old = await before
                expect(decodeJwt(old).aud).toBe('acme')
                expect(old).not.toBe(after)
                expect(await client.getToken()).toBe(after)
                expect(calls).toBe(3)
            })
        })
    })

    describe('default transport', () => {
        it('POSTs through the global fetch with Content-Type application/x-www-form-urlencoded', async () => {
            const real = bridge(keys)
            const sent: Request[] = []
            vi.stubGlobal('fetch', async (input: string, init: RequestInit) => {
                const request = new Request(input, init)
                sent.push(request.clone())
                return real.send(request)
            })
            const client = createBridgeClient({ url: BRIDGE_URL.clerk, audience: 'acme', getIdpToken: real.idpToken, now: real.now })
            const token = await client.getToken()
            expect(decodeJwt(token).aud).toBe('acme')
            expect(sent).toHaveLength(1)
            expect(sent[0]!.url).toBe(TOKEN_URL)
            expect(sent[0]!.method).toBe('POST')
            expect(sent[0]!.headers.get('content-type')).toBe(FORM)
            // Decoded by hand: workerd warns when .text() reads a form body
            expect(new TextDecoder().decode(await sent[0]!.arrayBuffer())).toMatch(/^grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=/)
        })

        it('is used for a transport given as undefined, as every optional option takes undefined', async () => {
            const real = bridge(keys)
            vi.stubGlobal('fetch', async (input: string, init: RequestInit) => real.send(new Request(input, init)))
            const client = createBridgeClient({
                url: BRIDGE_URL.clerk,
                audience: 'acme',
                getIdpToken: real.idpToken,
                transport: undefined,
                refreshBeforeSeconds: undefined,
                now: undefined,
            })
            expect(decodeJwt(await client.getToken()).aud).toBe('acme')
        })

        it('reads a body that is not JSON as a bad response', async () => {
            vi.stubGlobal('fetch', async () => new Response('<html>Bad gateway</html>', { status: 502, headers: { 'content-type': 'text/html' } }))
            const client = createBridgeClient({ url: BRIDGE_URL.clerk, audience: 'acme', getIdpToken: async () => 'token' })
            expect(await bridgeError(client.getToken())).toMatchObject({ status: 502, error: 'bad_response' })
        })
    })
})
