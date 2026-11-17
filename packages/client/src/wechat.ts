import { formBody, isRecord } from './form.js'
import { BridgeError, type Transport } from './index.js'

// Declare only the wx APIs used here to avoid a dependency on platform typings.
interface WxFailure {
    errMsg?: string
}

interface Wx {
    request(options: {
        url: string
        method: 'POST'
        header: Record<string, string>
        data: string
        dataType: 'json'
        success(result: { statusCode: number; data: unknown }): void
        fail(error: WxFailure): void
    }): unknown
    login(options: { success(result: { code?: string }): void; fail(error: WxFailure): void }): void
}

declare const wx: Wx

export interface CasdoorMiniProgramOptions {
    /** The Casdoor server, without a trailing slash. */
    casdoorUrl: string
    /** The client id of the Casdoor application the mini program signs in to. */
    clientId: string
    /** How the request to Casdoor is sent. Default: `wxRequestTransport`. */
    transport?: Transport | undefined
}

const FORM = 'application/x-www-form-urlencoded'

/**
 * A `Transport` over `wx.request`, for WeChat mini programs, which have no `fetch`. Rejects with an `Error` holding
 * `wx.request`'s `errMsg` when no answer arrives.
 */
export const wxRequestTransport: Transport = ({ url, body }) =>
    new Promise((resolve, reject) => {
        // wx.request calls success whatever the status, and fail only when no answer arrived
        wx.request({
            url,
            method: 'POST',
            header: { 'content-type': FORM },
            data: body,
            dataType: 'json',
            success: (result) => resolve({ status: result.statusCode, body: result.data }),
            fail: (error) => reject(new Error(failure(error, 'wx.request failed'))),
        })
    })

/**
 * A `getIdpToken` for `createBridgeClient` in a WeChat mini program that signs in through Casdoor. Each call gets a
 * new `wx.login` code and exchanges it at Casdoor, which holds the WeChat app secret, for a Casdoor access token.
 * Casdoor's errors throw `BridgeError`; a failed `wx.login` rejects with an `Error`.
 */
export function casdoorMiniProgramIdpToken(options: CasdoorMiniProgramOptions): () => Promise<string> {
    const { casdoorUrl, clientId } = options
    const transport = options.transport ?? wxRequestTransport
    return async () => {
        const code = await wxLoginCode()
        const request = {
            url: `${casdoorUrl}/api/login/oauth/access_token`,
            body: formBody([
                ['client_id', clientId],
                ['code', code],
                ['tag', 'wechat_miniprogram'],
            ]),
        }
        let answer: { status: number; body: unknown }
        try {
            answer = await transport(request)
        } catch {
            throw new BridgeError(0, 'network')
        }
        return accessToken(answer.status, answer.body)
    }
}

function wxLoginCode(): Promise<string> {
    return new Promise((resolve, reject) => {
        wx.login({
            success: (result) => {
                if (typeof result.code === 'string' && result.code !== '') resolve(result.code)
                else reject(new Error('wx.login gave no code'))
            },
            fail: (error) => reject(new Error(failure(error, 'wx.login failed'))),
        })
    })
}

// Read only token/error fields: `code` contains WeChat's session_key and must not escape this response.
function accessToken(status: number, body: unknown): string {
    if (!isRecord(body)) throw new BridgeError(status, 'bad_response')
    if (status === 200) {
        const camelCase = body.accessToken
        // Casdoor sends accessToken; its documentation shows access_token
        const token = typeof camelCase === 'string' && camelCase !== '' ? camelCase : body.access_token
        if (typeof token === 'string' && token !== '') return token
    }
    const error = body.error
    if (typeof error === 'string' && error !== '') throw new BridgeError(status, error)
    if (body.status === 'error') throw new BridgeError(status, 'casdoor_error')
    throw new BridgeError(status, 'bad_response')
}

function failure(error: WxFailure | undefined, fallback: string): string {
    const message = error?.errMsg
    return typeof message === 'string' && message !== '' ? message : fallback
}
