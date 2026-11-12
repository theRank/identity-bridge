import type { Deps } from '../../src/types'

export interface FetchCall {
    url: string
    method: string
    headers: Headers
    body: string
    redirect: string
    signal: AbortSignal | undefined
}

export type Responder = (call: FetchCall) => Response | Promise<Response>

// A server that never answers: only an aborted signal ends the call
export const hang: Responder = () => new Promise<never>(() => {})

// Records every call, then answers through `respond`. Like a real fetch it rejects with the signal's reason
// once the signal aborts; `ignoreSignal` models a runtime whose fetch cannot be aborted.
export function fakeFetch(respond: Responder, options: { ignoreSignal?: boolean } = {}): { fetch: Deps['fetch']; calls: FetchCall[] } {
    const calls: FetchCall[] = []
    const fetch = async (input: Request | string, init?: RequestInit): Promise<Response> => {
        const request = new Request(input, init)
        const signal = init?.signal ?? (input instanceof Request ? input.signal : undefined)
        const call: FetchCall = {
            url: request.url,
            method: request.method,
            headers: request.headers,
            // Decoded by hand: workerd warns when .text() reads a type such as application/secevent+jwt
            body: new TextDecoder().decode(await request.arrayBuffer()),
            redirect: request.redirect,
            signal,
        }
        calls.push(call)
        if (!signal || options.ignoreSignal) return respond(call)
        signal.throwIfAborted()
        return new Promise<Response>((resolve, reject) => {
            const abort = () => reject(signal.reason)
            signal.addEventListener('abort', abort, { once: true })
            Promise.resolve()
                .then(() => respond(call))
                .then(resolve, reject)
                .finally(() => signal.removeEventListener('abort', abort))
        })
    }
    return { fetch, calls }
}
