import { describe, expect, it } from 'vitest'
import { empty, json, oauthError, readBody } from '../src/http'
import type { LogCode, OAuthErrorCode } from '../src/types'

const TOKEN_URL = 'https://bridge.example/token'
const encoder = new TextEncoder()

const post = (body: BodyInit | null, headers: Record<string, string> = {}) => new Request(TOKEN_URL, { method: 'POST', body, headers })

function stream(chunks: Uint8Array[]) {
    const state = { pulls: 0, cancelled: false }
    const body = new ReadableStream<Uint8Array>({
        pull(controller) {
            const chunk = chunks[state.pulls++]
            if (chunk) controller.enqueue(chunk)
            else controller.close()
        },
        cancel() {
            state.cancelled = true
        },
    })
    return { body, state }
}

describe('readBody', () => {
    it('returns a body of exactly the limit', async () => {
        expect(await readBody(post('a'.repeat(16)), 16)).toBe('a'.repeat(16))
    })

    it('returns null for a body one byte over the limit', async () => {
        expect(await readBody(post('a'.repeat(17)), 16)).toBeNull()
    })

    it('counts bytes, not characters', async () => {
        expect(await readBody(post('éa'), 3)).toBe('éa')
        expect(await readBody(post('éé'), 3)).toBeNull()
    })

    it('reads a missing body as empty', async () => {
        expect(await readBody(new Request(TOKEN_URL, { method: 'POST' }), 16)).toBe('')
        expect(await readBody(new Request(TOKEN_URL), 16)).toBe('')
    })

    it('enforces the limit on a streamed body without Content-Length', async () => {
        const atLimit = stream([encoder.encode('aaaa'), encoder.encode('aaaa')])
        expect(await readBody(post(atLimit.body), 8)).toBe('aaaaaaaa')

        const over = stream([encoder.encode('aaaa'), encoder.encode('aaaa'), encoder.encode('a')])
        expect(await readBody(post(over.body), 8)).toBeNull()
    })

    it('does not trust a Content-Length smaller than the body', async () => {
        expect(await readBody(post('a'.repeat(100), { 'content-length': '10' }), 16)).toBeNull()
    })

    it('counts the bytes of a stream whose Content-Length claims fewer, and stops reading it', async () => {
        const { body, state } = stream(Array.from({ length: 25 }, () => encoder.encode('aaaa')))
        const lying = post(body, { 'content-length': '10' })
        // workerd keeps the header and streams every byte, so only the byte count can refuse this body
        expect(lying.headers.get('content-length')).toBe('10')
        expect(await readBody(lying, 16)).toBeNull()
        expect(state.cancelled).toBe(true)
        expect(state.pulls).toBeLessThan(25)
    })

    it('refuses a declared Content-Length over the limit without reading the body', async () => {
        const never = new ReadableStream<Uint8Array>({ pull: () => new Promise<void>(() => {}) })
        expect(await readBody(post(never, { 'content-length': '17' }), 16)).toBeNull()
    })

    it('stops reading and cancels the stream once over the limit', async () => {
        const { body, state } = stream(Array.from({ length: 100 }, () => encoder.encode('aaaa')))
        expect(await readBody(post(body), 10)).toBeNull()
        expect(state.cancelled).toBe(true)
        expect(state.pulls).toBeLessThan(10)
    })

    it('decodes a character split across chunks', async () => {
        const [first, second] = [...encoder.encode('é')]
        const { body } = stream([new Uint8Array([0x61, first!]), new Uint8Array([second!, 0x62])])
        expect(await readBody(post(body), 16)).toBe('aéb')
    })

    it('keeps a leading byte order mark, so the text is exactly what was signed', async () => {
        expect(await readBody(post('﻿{"type":"user.created"}'), 64)).toBe('﻿{"type":"user.created"}')
        const { body } = stream([new Uint8Array([0xef, 0xbb]), new Uint8Array([0xbf, 0x7b, 0x7d])])
        expect(await readBody(post(body), 64)).toBe('﻿{}')
    })
})

describe('json', () => {
    it('answers the status with a JSON body', async () => {
        const response = json(201, { status: 'ok' })
        expect(response.status).toBe(201)
        expect(response.headers.get('content-type')).toBe('application/json')
        expect(await response.json()).toEqual({ status: 'ok' })
    })

    it('adds the headers it is given', () => {
        const response = json(200, {}, { 'cache-control': 'public, max-age=300' })
        expect(response.headers.get('cache-control')).toBe('public, max-age=300')
        expect(response.headers.get('content-type')).toBe('application/json')
    })
})

describe('empty', () => {
    it('answers the status without a body or content type', async () => {
        const response = empty(404)
        expect(response.status).toBe(404)
        expect(response.headers.get('content-type')).toBeNull()
        expect(await response.text()).toBe('')
    })

    it('adds the headers it is given', () => {
        expect(empty(405, { allow: 'GET' }).headers.get('allow')).toBe('GET')
    })
})

describe('oauthError', () => {
    const SUBJECT_TOKEN_CODES: LogCode[] = [
        'malformed_token',
        'untrusted_issuer',
        'bad_algorithm',
        'bad_signature',
        'unknown_key',
        'expired',
        'too_old',
        'not_yet_valid',
        'missing_claim',
        'claim_mismatch',
        'client_mismatch',
        'bad_uid',
    ]
    const table: [number, OAuthErrorCode, LogCode[], string][] = [
        [400, 'invalid_request', ['bad_request'], 'The request is malformed.'],
        [400, 'invalid_request', SUBJECT_TOKEN_CODES, 'The subject token is not acceptable.'],
        [400, 'invalid_target', ['unknown_product', 'bad_request'], 'The requested audience is not available.'],
        [400, 'invalid_scope', ['bad_request'], 'Scopes are not supported.'],
        [400, 'unsupported_grant_type', ['unsupported_grant'], 'Only token exchange is supported.'],
        [413, 'invalid_request', ['too_large'], 'The request is too large.'],
        [503, 'temporarily_unavailable', ['jwks_unavailable'], 'The identity provider is unavailable.'],
        [500, 'server_error', ['runtime_unavailable', 'internal_error'], 'The service failed.'],
    ]
    const cases = table.flatMap(([status, error, codes, description]) => codes.map((code) => [status, error, code, description] as const))

    it.each(cases)('%i %s for %s says "%s"', async (status, error, code, description) => {
        const response = oauthError(status, error, code)
        expect(response.status).toBe(status)
        expect(await response.json()).toEqual({ error, error_description: description })
        expect(response.headers.get('content-type')).toBe('application/json')
        expect(response.headers.get('cache-control')).toBe('no-store')
        expect(response.headers.get('pragma')).toBe('no-cache')
        expect(response.headers.get('vary')).toBe('Origin')
    })

    it('adds extra headers, such as CORS, and keeps its own', () => {
        const response = oauthError(400, 'invalid_request', 'bad_signature', {
            'access-control-allow-origin': 'https://app.example',
            'cache-control': 'public, max-age=300',
        })
        expect(response.headers.get('access-control-allow-origin')).toBe('https://app.example')
        expect(response.headers.get('cache-control')).toBe('no-store')
        expect(response.headers.get('vary')).toBe('Origin')
    })

    it.each([
        [400, 'invalid_request', 'too_large'],
        [413, 'invalid_request', 'bad_request'],
        [400, 'invalid_request', 'jwks_unavailable'],
        [400, 'invalid_request', 'ignored'],
        [400, 'invalid_scope', 'unknown_product'],
        [400, 'server_error', 'internal_error'],
        [503, 'temporarily_unavailable', 'bad_signature'],
        [500, 'temporarily_unavailable', 'jwks_unavailable'],
    ] as const)('refuses %i %s for %s, which no row of the error table describes', (status, error, code) => {
        expect(() => oauthError(status, error, code)).toThrow()
    })
})
