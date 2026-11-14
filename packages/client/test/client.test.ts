import { decodeJwt, decodeProtectedHeader } from 'jose'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { BridgeError, createBridgeClient, type Transport } from '../src/index'
import { BRIDGE_URL, bridge, FORM, generateKeys, rejection, until, type Bridge, type BridgeOptions, type Keys } from './bridge'

const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
const JWT_TYPE = 'urn:ietf:params:oauth:token-type:jwt'
const TOKEN_URL = `${BRIDGE_URL.clerk}/token`

let keys: Keys

beforeAll(async () => {
    keys = await generateKeys()
})

afterEach(() => {
    vi.unstubAllGlobals()
})

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

        it('keeps the token in memory only', async () => {
            const storage = { setItem: vi.fn(), getItem: vi.fn() }
            vi.stubGlobal('localStorage', storage)
            vi.stubGlobal('sessionStorage', storage)
            const { client } = setup()
            await client.getToken()
            expect(storage.setItem).not.toHaveBeenCalled()
            expect(storage.getItem).not.toHaveBeenCalled()
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

        it('reads a body that is not JSON as a bad response', async () => {
            vi.stubGlobal('fetch', async () => new Response('<html>Bad gateway</html>', { status: 502, headers: { 'content-type': 'text/html' } }))
            const client = createBridgeClient({ url: BRIDGE_URL.clerk, audience: 'acme', getIdpToken: async () => 'token' })
            expect(await bridgeError(client.getToken())).toMatchObject({ status: 502, error: 'bad_response' })
        })
    })
})
