import { formBody, isRecord } from './form.js'
import { BridgeError, type Transport } from './index.js'

// The members of the mini program's wx global used here, declared rather than taken from a typings package
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
    // The Casdoor instance, without a trailing slash
    casdoorUrl: string
    // The client id of the Casdoor application the mini program signs in to
    clientId: string
    transport?: Transport
}

const FORM = 'application/x-www-form-urlencoded'

// wx.request calls success whatever the status, and fail only when no answer arrived
export const wxRequestTransport: Transport = ({ url, body }) =>
    new Promise((resolve, reject) => {
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

// A getIdpToken for createBridgeClient: a wx.login code exchanged at Casdoor, which holds the WeChat app secret
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

// Reads the token and the error members only: the answer's `code` is WeChat's session_key, which must never be
// read, kept or logged
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
