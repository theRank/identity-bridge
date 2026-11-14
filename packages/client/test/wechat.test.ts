import { decodeJwt } from 'jose'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { BridgeError, createBridgeClient } from '../src/index'
import { casdoorMiniProgramIdpToken, wxRequestTransport } from '../src/wechat'
import { BRIDGE_URL, bridge, FORM, generateKeys, MINI_PROGRAM_CLIENT, rejection, type Keys, type TransportCall } from './bridge'

const CASDOOR_URL = 'https://casdoor.example'
const CASDOOR_TOKEN_URL = `${CASDOOR_URL}/api/login/oauth/access_token`
// What Casdoor's Token object carries in `code` for a mini program login: WeChat's session_key
const SESSION_KEY = 'session-key-marker-tiihtNczf5v6AKRyjwEUhQ=='

interface WxRequestOptions {
    url: string
    method: string
    header: Record<string, string>
    data: string
    dataType: string
    success(result: { statusCode: number; data: unknown }): void
    fail(error: { errMsg: string }): void
}

interface WxLoginOptions {
    success(result: { code?: string }): void
    fail(error: { errMsg: string }): void
}

interface WxHandlers {
    request?(options: WxRequestOptions): void
    login?(options: WxLoginOptions): void
}

let keys: Keys

beforeAll(async () => {
    keys = await generateKeys()
})

afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
})

// The wx global of a mini program; wx.login hands out a new code on every call by default
function stubWx(handlers: WxHandlers = {}) {
    let codes = 0
    const wx = {
        request: vi.fn((options: WxRequestOptions) => {
            if (handlers.request) handlers.request(options)
            else options.fail({ errMsg: 'request:fail no handler' })
        }),
        login: vi.fn((options: WxLoginOptions) => {
            if (handlers.login) handlers.login(options)
            else options.success({ code: `wx-login-code-${++codes}` })
        }),
    }
    vi.stubGlobal('wx', wx)
    return wx
}

// Casdoor's Token object for a mini program login, as its source serializes it
function casdoorTokenBody(accessToken: string): Record<string, unknown> {
    return { accessToken, expiresIn: 604800, refreshToken: 'refresh-token', idToken: 'id-token', tokenType: 'Bearer', scope: 'read', code: SESSION_KEY }
}

// Records every way the object is read
function watched(target: Record<string, unknown>) {
    const reads: string[] = []
    const proxy = new Proxy(target, {
        get(object, key, receiver) {
            reads.push(String(key))
            return Reflect.get(object, key, receiver)
        },
        has(object, key) {
            reads.push(`has ${String(key)}`)
            return Reflect.has(object, key)
        },
        ownKeys(object) {
            reads.push('ownKeys')
            return Reflect.ownKeys(object)
        },
        getOwnPropertyDescriptor(object, key) {
            reads.push(`descriptor ${String(key)}`)
            return Reflect.getOwnPropertyDescriptor(object, key)
        },
    })
    return { proxy, reads }
}

function spyOnConsole() {
    return (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) => vi.spyOn(console, method))
}

describe('wxRequestTransport', () => {
    it('sends wx.request a POST with a form Content-Type, the body as data, and dataType json', async () => {
        const wx = stubWx({ request: (options) => options.success({ statusCode: 200, data: {} }) })
        await wxRequestTransport({ url: `${BRIDGE_URL.casdoor}/token`, body: 'grant_type=x&audience=acme' })
        expect(wx.request).toHaveBeenCalledTimes(1)
        expect(wx.request.mock.calls[0]![0]).toStrictEqual({
            url: `${BRIDGE_URL.casdoor}/token`,
            method: 'POST',
            header: { 'content-type': FORM },
            data: 'grant_type=x&audience=acme',
            dataType: 'json',
            success: expect.any(Function),
            fail: expect.any(Function),
        })
    })

    it.each([200, 400, 503])('resolves success with status %i as the status and the data as the body', async (statusCode) => {
        const data = { error: 'invalid_request' }
        stubWx({ request: (options) => options.success({ statusCode, data }) })
        expect(await wxRequestTransport({ url: `${BRIDGE_URL.casdoor}/token`, body: '' })).toStrictEqual({ status: statusCode, body: data })
    })

    it('rejects on fail', async () => {
        stubWx({ request: (options) => options.fail({ errMsg: 'request:fail timeout' }) })
        const error = await rejection(wxRequestTransport({ url: `${BRIDGE_URL.casdoor}/token`, body: '' }))
        expect(error).toBeInstanceOf(Error)
        expect((error as Error).message).toBe('request:fail timeout')
    })

    it('carries an exchange with the real bridge as the client transport', async () => {
        const real = bridge(keys, { deployment: 'casdoor' })
        stubWx({
            request: (options) => {
                const request = new Request(options.url, { method: options.method, headers: options.header, body: options.data })
                real.send(request).then(async (response) => options.success({ statusCode: response.status, data: await response.json() }))
            },
        })
        const client = createBridgeClient({ url: BRIDGE_URL.casdoor, audience: 'acme', getIdpToken: real.idpToken, transport: wxRequestTransport, now: real.now })
        expect(decodeJwt(await client.getToken())).toMatchObject({ iss: BRIDGE_URL.casdoor, aud: 'acme' })
    })
})

describe('casdoorMiniProgramIdpToken', () => {
    it('logs in with wx.login and posts client_id, the code and the mini program tag to Casdoor', async () => {
        const wx = stubWx()
        const transport = vi.fn(async () => ({ status: 200, body: casdoorTokenBody('casdoor-access-token') }))
        const getIdpToken = casdoorMiniProgramIdpToken({ casdoorUrl: CASDOOR_URL, clientId: MINI_PROGRAM_CLIENT, transport })
        expect(await getIdpToken()).toBe('casdoor-access-token')
        expect(wx.login).toHaveBeenCalledTimes(1)
        expect(wx.login.mock.calls[0]![0]).toStrictEqual({ success: expect.any(Function), fail: expect.any(Function) })
        expect(transport.mock.calls).toStrictEqual([
            [{ url: CASDOOR_TOKEN_URL, body: 'client_id=acme-mini-program-client&code=wx-login-code-1&tag=wechat_miniprogram' }],
        ])
    })

    it('encodes the form as URLSearchParams does', async () => {
        stubWx({ login: (options) => options.success({ code: 'a b+c/d=' }) })
        const transport = vi.fn(async () => ({ status: 200, body: casdoorTokenBody('casdoor-access-token') }))
        await casdoorMiniProgramIdpToken({ casdoorUrl: CASDOOR_URL, clientId: 'client id!', transport })()
        const fields = { client_id: 'client id!', code: 'a b+c/d=', tag: 'wechat_miniprogram' }
        expect(transport.mock.calls).toStrictEqual([[{ url: CASDOOR_TOKEN_URL, body: new URLSearchParams(fields).toString() }]])
    })

    it('accepts access_token, as Casdoor documents the answer', async () => {
        stubWx()
        const transport = async () => ({ status: 200, body: { access_token: 'documented-token', code: SESSION_KEY } })
        expect(await casdoorMiniProgramIdpToken({ casdoorUrl: CASDOOR_URL, clientId: MINI_PROGRAM_CLIENT, transport })()).toBe('documented-token')
    })

    it('posts through wx.request by default', async () => {
        const wx = stubWx({ request: (options) => options.success({ statusCode: 200, data: casdoorTokenBody('casdoor-access-token') }) })
        const getIdpToken = casdoorMiniProgramIdpToken({ casdoorUrl: CASDOOR_URL, clientId: MINI_PROGRAM_CLIENT })
        expect(await getIdpToken()).toBe('casdoor-access-token')
        expect(wx.request.mock.calls[0]![0]).toMatchObject({
            url: CASDOOR_TOKEN_URL,
            method: 'POST',
            header: { 'content-type': FORM },
            data: 'client_id=acme-mini-program-client&code=wx-login-code-1&tag=wechat_miniprogram',
            dataType: 'json',
        })
    })

    it('uses a new wx.login code on every call', async () => {
        const wx = stubWx()
        const transport = vi.fn(async (_: TransportCall) => ({ status: 200, body: casdoorTokenBody('casdoor-access-token') }))
        const getIdpToken = casdoorMiniProgramIdpToken({ casdoorUrl: CASDOOR_URL, clientId: MINI_PROGRAM_CLIENT, transport })
        await getIdpToken()
        await getIdpToken()
        expect(wx.login).toHaveBeenCalledTimes(2)
        expect(transport.mock.calls.map(([request]) => new URLSearchParams(request.body).get('code'))).toEqual(['wx-login-code-1', 'wx-login-code-2'])
    })

    describe('Casdoor errors', () => {
        it.each([
            ['{error, error_description} with 400', 400, { error: 'invalid_grant', error_description: 'the code is invalid' }, 'invalid_grant'],
            ['{error, error_description} with 401', 401, { error: 'invalid_client', error_description: 'client_id is wrong' }, 'invalid_client'],
            ['{status: "error", msg} with 200', 200, { status: 'error', msg: 'the code is invalid', data: '', data2: '' }, 'casdoor_error'],
            ['{status: "error", msg} with 400 from a request filter', 400, { status: 'error', msg: 'unauthorized operation', data: '' }, 'casdoor_error'],
            ['{status: "error", msg} with 413 from a request filter', 413, { status: 'error', msg: 'request body too large' }, 'casdoor_error'],
        ])('throws %s as BridgeError', async (_, status, body, error) => {
            stubWx()
            const transport = async () => ({ status, body })
            const thrown = await rejection(casdoorMiniProgramIdpToken({ casdoorUrl: CASDOOR_URL, clientId: MINI_PROGRAM_CLIENT, transport })())
            expect(thrown).toBeInstanceOf(BridgeError)
            expect(thrown).toMatchObject({ status, error })
            const text = `${(thrown as Error).message} ${JSON.stringify(thrown)}`
            expect(text).not.toContain('the code is invalid')
            expect(text).not.toContain('client_id is wrong')
        })

        it.each([
            ['a 200 without a token', 200, { expiresIn: 7200 }],
            ['a 200 whose accessToken is not a string', 200, { accessToken: 42 }],
            ['a 200 whose accessToken is empty', 200, { accessToken: '' }],
            ['a body that is not JSON', 502, '<html>Bad gateway</html>'],
            ['an error without an error member', 500, {}],
        ])('throws %s as BridgeError bad_response', async (_, status, body) => {
            stubWx()
            const transport = async () => ({ status, body })
            const thrown = await rejection(casdoorMiniProgramIdpToken({ casdoorUrl: CASDOOR_URL, clientId: MINI_PROGRAM_CLIENT, transport })())
            expect(thrown).toBeInstanceOf(BridgeError)
            expect(thrown).toMatchObject({ status, error: 'bad_response' })
        })

        it('throws a rejected transport as BridgeError network with status 0', async () => {
            stubWx()
            const transport = async () => {
                throw new Error('request:fail url not in domain list')
            }
            const thrown = await rejection(casdoorMiniProgramIdpToken({ casdoorUrl: CASDOOR_URL, clientId: MINI_PROGRAM_CLIENT, transport })())
            expect(thrown).toBeInstanceOf(BridgeError)
            expect(thrown).toMatchObject({ status: 0, error: 'network' })
        })
    })

    describe('wx.login failures', () => {
        it('rejects when wx.login fails, without calling Casdoor', async () => {
            stubWx({ login: (options) => options.fail({ errMsg: 'login:fail' }) })
            const transport = vi.fn()
            const thrown = await rejection(casdoorMiniProgramIdpToken({ casdoorUrl: CASDOOR_URL, clientId: MINI_PROGRAM_CLIENT, transport })())
            expect(thrown).toBeInstanceOf(Error)
            expect((thrown as Error).message).toContain('login:fail')
            expect(transport).not.toHaveBeenCalled()
        })

        it('rejects when wx.login gives no code', async () => {
            stubWx({ login: (options) => options.success({}) })
            const transport = vi.fn()
            expect(await rejection(casdoorMiniProgramIdpToken({ casdoorUrl: CASDOOR_URL, clientId: MINI_PROGRAM_CLIENT, transport })())).toBeInstanceOf(Error)
            expect(transport).not.toHaveBeenCalled()
        })
    })

    describe('the session_key in the answer', () => {
        it('is never read: only the token is', async () => {
            stubWx()
            const logged = spyOnConsole()
            const { proxy, reads } = watched(casdoorTokenBody('casdoor-access-token'))
            const token = await casdoorMiniProgramIdpToken({ casdoorUrl: CASDOOR_URL, clientId: MINI_PROGRAM_CLIENT, transport: async () => ({ status: 200, body: proxy }) })()
            expect(token).toBe('casdoor-access-token')
            expect(reads).toEqual(['accessToken'])
            for (const spy of logged) expect(spy).not.toHaveBeenCalled()
        })

        it('is never read when the answer is an error', async () => {
            stubWx()
            const logged = spyOnConsole()
            const { proxy, reads } = watched({ status: 'error', msg: 'the code is invalid', code: SESSION_KEY })
            const thrown = await rejection(
                casdoorMiniProgramIdpToken({ casdoorUrl: CASDOOR_URL, clientId: MINI_PROGRAM_CLIENT, transport: async () => ({ status: 200, body: proxy }) })(),
            )
            expect(thrown).toMatchObject({ error: 'casdoor_error' })
            expect(reads).not.toContain('code')
            expect(reads).not.toContain('ownKeys')
            expect(JSON.stringify(thrown)).not.toContain(SESSION_KEY)
            for (const spy of logged) expect(spy).not.toHaveBeenCalled()
        })
    })

    it('gives a Casdoor mini program token the real bridge exchanges', async () => {
        const real = bridge(keys, { deployment: 'casdoor' })
        const casdoorToken = await real.idpToken()
        const casdoorRequests: string[] = []
        stubWx({
            request: (options) => {
                if (options.url === CASDOOR_TOKEN_URL) {
                    casdoorRequests.push(options.data)
                    options.success({ statusCode: 200, data: casdoorTokenBody(casdoorToken) })
                    return
                }
                const request = new Request(options.url, { method: options.method, headers: options.header, body: options.data })
                real.send(request).then(async (response) => options.success({ statusCode: response.status, data: await response.json() }))
            },
        })
        const client = createBridgeClient({
            url: BRIDGE_URL.casdoor,
            audience: 'acme',
            getIdpToken: casdoorMiniProgramIdpToken({ casdoorUrl: CASDOOR_URL, clientId: MINI_PROGRAM_CLIENT }),
            transport: wxRequestTransport,
            now: real.now,
        })
        expect(decodeJwt(await client.getToken())).toMatchObject({ iss: BRIDGE_URL.casdoor, aud: 'acme', client_id: 'acme' })
        expect(casdoorRequests).toEqual(['client_id=acme-mini-program-client&code=wx-login-code-1&tag=wechat_miniprogram'])
    })
})
