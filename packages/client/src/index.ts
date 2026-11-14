import { formBody, isRecord } from './form.js'

// POSTs body as application/x-www-form-urlencoded to url and gives back the status and the parsed JSON answer
export type Transport = (request: { url: string; body: string }) => Promise<{ status: number; body: unknown }>

export interface BridgeClientOptions {
    // The bridge issuer, without a trailing slash
    url: string
    // The product id
    audience: string
    // A fresh identity provider token on every call
    getIdpToken(): Promise<string>
    transport?: Transport
    refreshBeforeSeconds?: number
    // Milliseconds since the epoch
    now?(): number
}

export interface BridgeClient {
    getToken(): Promise<string>
    clear(): void
}

// `error` is the OAuth error of the answer, or `network` or `bad_response`. The error_description is left out on
// purpose: callers branch on `error`, and the description is for people.
export class BridgeError extends Error {
    override name = 'BridgeError'
    readonly status: number
    readonly error: string

    constructor(status: number, error: string) {
        super(`identity-bridge: ${error} (status ${status})`)
        this.status = status
        this.error = error
    }
}

// The client compiles without the DOM lib; these are the parts of fetch and setTimeout it uses
interface FetchResponse {
    status: number
    text(): Promise<string>
}
declare function fetch(url: string, init: { method: 'POST'; headers: Record<string, string>; body: string }): Promise<FetchResponse>
declare function setTimeout(callback: () => void, ms: number): unknown

const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
const JWT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt'
const FORM = 'application/x-www-form-urlencoded'
const RETRY_DELAYS_MS = [250, 1000]

interface Issued {
    token: string
    refreshAt: number
    expiresAt: number
}

export function createBridgeClient(options: BridgeClientOptions): BridgeClient {
    const { url, audience, refreshBeforeSeconds = 60 } = options
    if (!(refreshBeforeSeconds >= 0)) throw new RangeError('refreshBeforeSeconds must be 0 or more')
    const transport = options.transport ?? fetchTransport
    const now = () => (options.now ? options.now() : Date.now())
    let cached: Issued | undefined
    let pending: Promise<string> | undefined

    // A refresh that cannot reach the bridge, even after its retries, keeps the token it was refreshing while that
    // token is valid and was neither cleared nor replaced meanwhile. A failure of getIdpToken is passed on as it is.
    async function refresh(current: Issued | undefined): Promise<Issued> {
        const subjectToken = await options.getIdpToken()
        try {
            return await exchange(subjectToken)
        } catch (error) {
            if (current !== undefined && cached === current && unreachable(error) && now() < current.expiresAt) return current
            throw error
        }
    }

    async function exchange(subjectToken: string): Promise<Issued> {
        const request = {
            url: `${url}/token`,
            body: formBody([
                ['grant_type', TOKEN_EXCHANGE],
                ['subject_token', subjectToken],
                ['subject_token_type', JWT_TOKEN_TYPE],
                ['audience', audience],
            ]),
        }
        // Retries reuse the IdP token: getting another could prompt the user, or spend a single-use code
        for (let attempt = 0; ; attempt++) {
            const answer = await send(transport, request)
            const retry = answer === undefined || (answer.status === 503 && oauthError(answer.body) === 'temporarily_unavailable')
            if (retry && attempt < RETRY_DELAYS_MS.length) {
                await sleep(RETRY_DELAYS_MS[attempt]!)
                continue
            }
            if (answer === undefined) throw new BridgeError(0, 'network')
            return issued(answer, now(), refreshBeforeSeconds)
        }
    }

    return {
        getToken() {
            if (cached !== undefined && now() < cached.refreshAt) return Promise.resolve(cached.token)
            if (pending === undefined) {
                const current: Promise<string> = refresh(cached).then(
                    (result) => {
                        // Not cached once clear() has dropped this exchange
                        if (pending === current) {
                            cached = result
                            pending = undefined
                        }
                        return result.token
                    },
                    (error: unknown) => {
                        if (pending === current) pending = undefined
                        throw error
                    },
                )
                pending = current
            }
            return pending
        },

        clear() {
            cached = undefined
            pending = undefined
        },
    }
}

// undefined for a rejected transport. Its reason is dropped, as a custom transport may quote the request, which
// holds the IdP token.
async function send(transport: Transport, request: { url: string; body: string }): Promise<{ status: number; body: unknown } | undefined> {
    try {
        return await transport(request)
    } catch {
        return undefined
    }
}

// The lifetime is measured from the answer's arrival by the client's own clock, so a skewed clock does not matter
function issued(answer: { status: number; body: unknown }, arrivedAt: number, refreshBeforeSeconds: number): Issued {
    const { status, body } = answer
    if (status !== 200) throw new BridgeError(status, oauthError(body) ?? 'bad_response')
    const token = isRecord(body) ? body.access_token : undefined
    const expiresIn = isRecord(body) ? body.expires_in : undefined
    if (typeof token !== 'string' || token === '' || typeof expiresIn !== 'number' || !(expiresIn > 0) || expiresIn === Infinity) {
        throw new BridgeError(status, 'bad_response')
    }
    // Half the lifetime at most, or a short token lifetime would make every call exchange
    const margin = Math.min(refreshBeforeSeconds, expiresIn / 2)
    return { token, refreshAt: arrivedAt + (expiresIn - margin) * 1000, expiresAt: arrivedAt + expiresIn * 1000 }
}

function unreachable(error: unknown): boolean {
    return error instanceof BridgeError && (error.error === 'network' || error.error === 'temporarily_unavailable')
}

function oauthError(body: unknown): string | undefined {
    const error = isRecord(body) ? body.error : undefined
    return typeof error === 'string' && error !== '' ? error : undefined
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
        setTimeout(resolve, ms)
    })
}

// A string body would otherwise go out as text/plain, which the bridge refuses
const fetchTransport: Transport = async ({ url, body }) => {
    const response = await fetch(url, { method: 'POST', headers: { 'content-type': FORM }, body })
    return { status: response.status, body: parseJson(await response.text()) }
}

function parseJson(text: string): unknown {
    try {
        return JSON.parse(text)
    } catch {
        return undefined
    }
}
