import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { jwksFetch, JwksFetchError } from '../src/idp/fetch'
import { fakeFetch, hang, type Responder } from './helpers/fetch'

const JWKS_URI = 'https://clerk.acme.example/.well-known/jwks.json'
const JWKS = {
    keys: [{ kty: 'EC', crv: 'P-256', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0' }],
}

// The options jose passes to its fetch
function init(signal: AbortSignal = new AbortController().signal) {
    return {
        method: 'GET' as const,
        redirect: 'manual' as const,
        signal,
        headers: new Headers({ accept: 'application/json, application/jwk-set+json', 'user-agent': 'jose/v6.2.17' }),
    }
}

async function rejection(pending: Promise<unknown>): Promise<unknown> {
    return pending.then(
        () => undefined,
        (caught: unknown) => caught,
    )
}

async function load(respond: Responder, options: { ignoreSignal?: boolean } = {}): Promise<Response> {
    return jwksFetch(fakeFetch(respond, options).fetch)(JWKS_URI, init())
}

// A body that sends nothing and never ends
function stalledBody(): ReadableStream<Uint8Array> {
    return new ReadableStream({ start() {} })
}

describe('jwksFetch', () => {
    it('forwards the url, method, redirect mode, headers and the signal itself', async () => {
        const { fetch, calls } = fakeFetch(() => Response.json(JWKS))
        const options = init()
        await jwksFetch(fetch)(JWKS_URI, options)
        expect(calls).toHaveLength(1)
        expect(calls[0]).toMatchObject({ url: JWKS_URI, method: 'GET', redirect: 'manual', body: '' })
        expect(calls[0]!.signal).toBe(options.signal)
        expect(calls[0]!.headers.get('accept')).toBe('application/json, application/jwk-set+json')
        expect(calls[0]!.headers.get('user-agent')).toBe('jose/v6.2.17')
    })

    it('answers with a fresh 200 response holding the parsed body', async () => {
        const original = Response.json(JWKS, { headers: { 'cache-control': 'max-age=60' } })
        const response = await load(() => original)
        expect(response).not.toBe(original)
        expect(response.status).toBe(200)
        expect(await response.json()).toStrictEqual(JWKS)
    })

    it('passes the body text on as it was received, as JSON', async () => {
        const text = '{\n  "keys": [ { "kty": "EC" } ]\n}\n'
        const response = await load(() => new Response(text, { headers: { 'content-type': 'application/jwk-set+json' } }))
        expect(response.headers.get('content-type')).toBe('application/json')
        expect(await response.text()).toBe(text)
    })

    it('reads any JSON object whatever its content type, leaving the JWKS checks to jose', async () => {
        const body = JSON.stringify({ keys: 'not an array' })
        const response = await load(() => new Response(body, { headers: { 'content-type': 'text/plain' } }))
        expect(await response.json()).toStrictEqual({ keys: 'not an array' })
    })

    it.each([
        ['201', () => Response.json(JWKS, { status: 201 })],
        ['204', () => new Response(null, { status: 204 })],
        ['302', () => new Response(null, { status: 302, headers: { location: 'https://evil.example/jwks' } })],
        ['304', () => new Response(null, { status: 304 })],
        ['404', () => new Response('not found', { status: 404 })],
        ['500', () => Response.json(JWKS, { status: 500 })],
        ['503', () => new Response('<html>unavailable</html>', { status: 503, headers: { 'content-type': 'text/html' } })],
    ] satisfies [string, Responder][])('fails with JwksFetchError for status %s', async (_, respond) => {
        expect(await rejection(load(respond))).toBeInstanceOf(JwksFetchError)
    })

    it('cancels the body of a response whose status is not 200', async () => {
        let cancelled = false
        const body = new ReadableStream({
            pull(controller) {
                controller.enqueue(new TextEncoder().encode('<html>'))
            },
            cancel() {
                cancelled = true
            },
        })
        expect(await rejection(load(() => new Response(body, { status: 500 })))).toBeInstanceOf(JwksFetchError)
        expect(cancelled).toBe(true)
    })

    it('still fails with JwksFetchError when cancelling the body fails', async () => {
        const body = new ReadableStream({
            cancel() {
                throw new TypeError('cannot cancel')
            },
        })
        expect(await rejection(load(() => new Response(body, { status: 502 })))).toBeInstanceOf(JwksFetchError)
    })

    it('fails with JwksFetchError when the fetch rejects', async () => {
        const error = await rejection(load(() => Promise.reject(new TypeError('Network connection lost.'))))
        expect(error).toBeInstanceOf(JwksFetchError)
    })

    it('fails with JwksFetchError when the fetch throws before returning a promise', async () => {
        const fetch = () => {
            throw new TypeError('Fetch API cannot load')
        }
        expect(await rejection(jwksFetch(fetch)(JWKS_URI, init()))).toBeInstanceOf(JwksFetchError)
    })

    it('fails with JwksFetchError when the body fails while being read', async () => {
        const body = new ReadableStream({
            pull(controller) {
                controller.error(new TypeError('connection reset'))
            },
        })
        expect(await rejection(load(() => new Response(body)))).toBeInstanceOf(JwksFetchError)
    })

    it.each([
        ['an HTML page', '<!doctype html><html><body>Sign in</body></html>'],
        ['an empty body', ''],
        ['truncated JSON', '{"keys": [{"kty": "RSA"'],
        ['an array', '[]'],
        ['a string', '"keys"'],
        ['a number', '42'],
        ['null', 'null'],
        ['true', 'true'],
    ])('fails with JwksFetchError for a 200 body that is not a JSON object: %s', async (_, body) => {
        expect(await rejection(load(() => new Response(body, { headers: { 'content-type': 'application/json' } })))).toBeInstanceOf(JwksFetchError)
    })

    it('fails with JwksFetchError once the signal aborts', async () => {
        const { fetch } = fakeFetch(hang)
        const controller = new AbortController()
        const pending = rejection(jwksFetch(fetch)(JWKS_URI, init(controller.signal)))
        controller.abort(new DOMException('The operation timed out.', 'TimeoutError'))
        expect(await pending).toBeInstanceOf(JwksFetchError)
    })

    it('gives a message that quotes nothing from the response', async () => {
        const error = await rejection(load(() => new Response('<html>secret-marker</html>', { status: 500 })))
        expect(error).toBeInstanceOf(JwksFetchError)
        expect((error as Error).name).toBe('JwksFetchError')
        expect((error as Error).message).not.toContain('secret-marker')
    })

    describe('its own timer', () => {
        beforeEach(() => {
            vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
        })

        afterEach(() => {
            vi.useRealTimers()
        })

        async function settlesAt(pending: Promise<unknown>, ms: number): Promise<unknown> {
            let settled = false
            const outcome = rejection(pending).finally(() => {
                settled = true
            })
            await vi.advanceTimersByTimeAsync(ms - 1)
            expect(settled).toBe(false)
            await vi.advanceTimersByTimeAsync(1)
            expect(settled).toBe(true)
            return outcome
        }

        it('ends a fetch that ignores its signal after 5 s', async () => {
            const pending = load(hang, { ignoreSignal: true })
            expect(await settlesAt(pending, 5000)).toBeInstanceOf(JwksFetchError)
        })

        it('ends a fetch whose signal never aborts after 5 s', async () => {
            expect(await settlesAt(load(hang), 5000)).toBeInstanceOf(JwksFetchError)
        })

        it('ends a body that never finishes after 5 s', async () => {
            expect(await settlesAt(load(() => new Response(stalledBody())), 5000)).toBeInstanceOf(JwksFetchError)
        })

        it('leaves no timer behind once the fetch settles', async () => {
            await load(() => Response.json(JWKS))
            expect(vi.getTimerCount()).toBe(0)
            await rejection(load(() => new Response(null, { status: 500 })))
            expect(vi.getTimerCount()).toBe(0)
        })
    })
})
