import { expect } from 'vitest'

// Sends a request to a runtime entry, whichever way that entry is reached: a direct call or real HTTP
export type Send = (path: string, init?: RequestInit) => Promise<Response>

export const FORM = { 'content-type': 'application/x-www-form-urlencoded' }

// What a runtime that failed to load answers
export async function expectFailureMode(send: Send): Promise<void> {
    const health = await send('/healthz')
    expect(health.status).toBe(503)
    expect(health.headers.get('cache-control')).toBe('no-store')
    expect(await health.json()).toEqual({ status: 'unavailable' })

    const token = await send('/token', { method: 'POST', headers: FORM, body: 'grant_type=x' })
    expect(token.status).toBe(500)
    expect(token.headers.get('cache-control')).toBe('no-store')
    expect(token.headers.get('vary')).toBe('Origin')
    expect(await token.json()).toEqual({ error: 'server_error', error_description: 'The service failed.' })

    const jwks = await send('/.well-known/jwks.json')
    expect(jwks.status).toBe(500)
    expect(await jwks.text()).toBe('')

    const webhook = await send('/webhooks/clerk-acme', { method: 'POST', body: '{}' })
    expect(webhook.status).toBe(500)
    expect(await webhook.text()).toBe('')

    const unknown = await send('/nope')
    expect(unknown.status).toBe(404)
    expect(await unknown.text()).toBe('')

    const wrongMethod = await send('/token', { method: 'GET' })
    expect(wrongMethod.status).toBe(405)
    expect(wrongMethod.headers.get('allow')).toBe('POST, OPTIONS')
    expect(await wrongMethod.text()).toBe('')
}

// The answers of a runtime that loaded, as far as they show without an IdP
export async function expectServing(send: Send, kid: string): Promise<void> {
    const health = await send('/healthz')
    expect(health.status).toBe(200)
    expect(await health.json()).toEqual({ status: 'ok' })

    const jwks = await send('/.well-known/jwks.json')
    expect(jwks.status).toBe(200)
    expect(await jwks.json()).toEqual({ keys: [expect.objectContaining({ kid, alg: 'ES256' })] })
}
