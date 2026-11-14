import { decodeJwt, decodeProtectedHeader } from 'jose'
import { handle } from '../../../src/app'
import { parseConfig } from '../../../src/config'
import { importSigningKeys } from '../../../src/keys'
import type { Runtime, SigningKeys } from '../../../src/types'
import { clerkConfig } from '../../../test/helpers/config'
import { fakeDeps } from '../../../test/helpers/deps'
import { fakeFetch } from '../../../test/helpers/fetch'
import { base64url, clerkClaims, NOW_SEC, signToken } from '../../../test/helpers/idp'
import { bridgeSigningKeys, idpJwks, rsaKeyPair, type IdpKeyPair } from '../../../test/helpers/keys'
import { CLERK_SECRET, svixSignature } from '../../../test/helpers/webhooks'

// The real bridge of the service's Clerk test deployment: access tokens from its token exchange, event tokens from
// its Clerk webhook relay, and its JWKS for the verifier

export const ISSUER = 'https://id.acme.example'
export const JWKS_URL = `${ISSUER}/.well-known/jwks.json`
export const EVENTS_URL = 'https://api.acme.example/identity/events'
export const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
export const JWT_TYPE = 'urn:ietf:params:oauth:token-type:jwt'

export const ADA = {
    email: 'ada@acme.example',
    phoneNumber: '+15555550100',
    name: 'Ada Lovelace',
    picture: 'https://img.clerk.example/ada.png',
}

export type ClerkEventType = 'user.created' | 'user.updated' | 'user.deleted'

export interface Keys {
    // An active key and a retired one, both published in the JWKS
    bridge: SigningKeys
    clerk: IdpKeyPair
}

export async function generateKeys(): Promise<Keys> {
    const [bridge, clerk] = await Promise.all([
        bridgeSigningKeys(1).then((generated) => importSigningKeys(generated.json)),
        rsaKeyPair({ kid: 'ins_2abcDEFghiJKLmnoPQRstuVWXyz' }),
    ])
    return { bridge, clerk }
}

export interface Bridge {
    // The bridge's routes, as the verifier's fetch option
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>
    // The URLs the verifier fetched
    fetched: string[]
    accessToken(claims?: Record<string, unknown>): Promise<string>
    eventToken(type: ClerkEventType): Promise<string>
}

// Minted at the fake clock's start, NOW_SEC
export function bridge(keys: Keys): Bridge {
    const { fetch: outbound, calls } = fakeFetch((call) => (call.url === EVENTS_URL ? new Response(null, { status: 202 }) : Response.json(idpJwks(keys.clerk))))
    const { deps } = fakeDeps({ fetch: outbound })
    const runtime: Runtime = { config: parseConfig(JSON.stringify(clerkConfig())), keys: keys.bridge, webhookSecret: () => CLERK_SECRET }
    const send = (request: Request) => handle(request, runtime, deps)
    const fetched: string[] = []
    let events = 0

    return {
        fetched,
        fetch(input, init) {
            const request = new Request(input, init)
            fetched.push(request.url)
            return send(request)
        },

        async accessToken(claims = {}) {
            const subjectToken = await signToken(keys.clerk, clerkClaims({ phone_number: ADA.phoneNumber, phone_number_verified: true, ...claims }))
            const body = new URLSearchParams({ grant_type: TOKEN_EXCHANGE, subject_token: subjectToken, subject_token_type: JWT_TYPE, audience: 'acme' })
            const response = await send(new Request(`${ISSUER}/token`, { method: 'POST', body }))
            if (response.status !== 200) throw new Error(`exchange failed: ${response.status}`)
            return ((await response.json()) as { access_token: string }).access_token
        },

        async eventToken(type) {
            const id = `msg_${++events}`
            const timestamp = String(NOW_SEC)
            const body = JSON.stringify({ type, object: 'event', data: clerkUser(type) })
            const headers = { 'svix-id': id, 'svix-timestamp': timestamp, 'svix-signature': await svixSignature(CLERK_SECRET, id, timestamp, body) }
            const response = await send(new Request(`${ISSUER}/webhooks/clerk-acme`, { method: 'POST', headers, body }))
            if (response.status !== 200) throw new Error(`relay failed: ${response.status}`)
            const delivery = calls.filter((call) => call.url === EVENTS_URL).at(-1)
            if (delivery === undefined) throw new Error('nothing delivered')
            return delivery.body
        },
    }
}

function clerkUser(type: ClerkEventType): Record<string, unknown> {
    const id = 'user_2pXkLm4NqR7sT9vW1xY3zB5cD8f'
    if (type === 'user.deleted') return { id, object: 'user', deleted: true, external_id: null }
    return {
        id,
        object: 'user',
        external_id: null,
        primary_email_address_id: 'idn_email',
        email_addresses: [{ id: 'idn_email', email_address: ADA.email, verification: { status: 'verified' } }],
        primary_phone_number_id: 'idn_phone',
        phone_numbers: [{ id: 'idn_phone', phone_number: ADA.phoneNumber, verification: { status: 'verified' } }],
        first_name: 'Ada',
        last_name: 'Lovelace',
        image_url: ADA.picture,
    }
}

export interface Edit {
    // A member set to undefined is removed
    header?: Record<string, unknown>
    claims?: Record<string, unknown>
    // The claims set as raw bytes, in place of `claims`
    payload?: string
}

// The token's header and claims edited, signed again with the bridge's active key. Signed with crypto.subtle, as jose
// refuses to sign some of the headers tests need, such as an unknown crit extension.
export async function resign(keys: Keys, token: string, edit: Edit): Promise<string> {
    const header = withEdits({ ...decodeProtectedHeader(token) }, edit.header)
    const payload = edit.payload ?? JSON.stringify(withEdits({ ...decodeJwt(token) }, edit.claims))
    const input = `${base64url(JSON.stringify(header))}.${base64url(payload)}`
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.bridge.privateKey, new TextEncoder().encode(input))
    return `${input}.${base64url(new Uint8Array(signature))}`
}

function withEdits(target: Record<string, unknown>, edits: Record<string, unknown> = {}): Record<string, unknown> {
    for (const [name, value] of Object.entries(edits)) {
        if (value === undefined) delete target[name]
        else target[name] = value
    }
    return target
}

// Captured before any test fakes timers: fake timers do not stop the real event loop
const realSetTimeout = globalThis.setTimeout.bind(globalThis)

export async function until(condition: () => boolean): Promise<void> {
    for (let turn = 0; !condition(); turn++) {
        if (turn === 1000) throw new Error('condition never held')
        await new Promise((resolve) => realSetTimeout(resolve, 0))
    }
}

export async function rejection(pending: Promise<unknown>): Promise<unknown> {
    return pending.then(
        () => {
            throw new Error('expected a rejection')
        },
        (caught: unknown) => caught,
    )
}
