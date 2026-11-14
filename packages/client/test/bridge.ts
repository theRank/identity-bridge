import { handle } from '../../../src/app'
import { parseConfig } from '../../../src/config'
import { importSigningKeys } from '../../../src/keys'
import type { Runtime, SigningKeys } from '../../../src/types'
import { casdoorConfig, clerkConfig } from '../../../test/helpers/config'
import { fakeDeps } from '../../../test/helpers/deps'
import { fakeFetch, type FetchCall, type Responder } from '../../../test/helpers/fetch'
import { casdoorClaims, clerkClaims, signToken } from '../../../test/helpers/idp'
import { bridgeSigningKeys, idpJwks, rsaKeyPair, type IdpKeyPair } from '../../../test/helpers/keys'
import type { Transport } from '../src/index'

// The real bridge behind a Transport, for a Clerk or a Casdoor deployment as the service's own tests configure them

export type Deployment = 'clerk' | 'casdoor'

export const FORM = 'application/x-www-form-urlencoded'
export const BRIDGE_URL: Record<Deployment, string> = { clerk: 'https://id.acme.example', casdoor: 'https://id.cn.acme.example' }
export const MINI_PROGRAM_CLIENT = 'acme-mini-program-client'

export interface Keys {
    bridge: SigningKeys
    clerk: IdpKeyPair
    casdoor: IdpKeyPair
}

export async function generateKeys(): Promise<Keys> {
    const [bridge, clerk, casdoor] = await Promise.all([
        bridgeSigningKeys().then((generated) => importSigningKeys(generated.json)),
        rsaKeyPair({ kid: 'ins_2abcDEFghiJKLmnoPQRstuVWXyz' }),
        rsaKeyPair({ kid: 'cert-built-in' }),
    ])
    return { bridge, clerk, casdoor }
}

export interface TransportCall {
    url: string
    body: string
}

export interface Answer {
    status: number
    body: unknown
}

export interface Bridge {
    transport: Transport
    // What the transport was given, recorded when called, and what the bridge answered, recorded when it answered
    requests: TransportCall[]
    answers: Answer[]
    // The bridge's own fetch calls, to the IdP's JWKS
    idpFetches: FetchCall[]
    send(request: Request): Promise<Response>
    // A token from the deployment's IdP, valid at the bridge's current time; Casdoor's for the mini program client
    idpToken(): Promise<string>
    now(): number
    advance(ms: number): void
}

export interface BridgeOptions {
    deployment?: Deployment
    tokenTtlSeconds?: number
    // Answers the bridge's fetch of the IdP JWKS; serves the IdP's key by default
    respond?: Responder
}

export function bridge(keys: Keys, options: BridgeOptions = {}): Bridge {
    const deployment = options.deployment ?? 'clerk'
    const doc: Record<string, unknown> = deployment === 'clerk' ? clerkConfig() : casdoorConfig()
    if (options.tokenTtlSeconds !== undefined) doc.tokenTtlSeconds = options.tokenTtlSeconds
    const idpKey = deployment === 'clerk' ? keys.clerk : keys.casdoor
    const { fetch, calls } = fakeFetch(options.respond ?? (() => Response.json(idpJwks(idpKey))))
    const { deps, advance } = fakeDeps({ fetch })
    const runtime: Runtime = {
        config: parseConfig(JSON.stringify(doc)),
        keys: keys.bridge,
        webhookSecret: () => {
            throw new Error('not read by these tests')
        },
    }
    const send = (request: Request) => handle(request, runtime, deps)
    const requests: TransportCall[] = []
    const answers: Answer[] = []
    const transport: Transport = async (request) => {
        requests.push(request)
        const response = await send(new Request(request.url, { method: 'POST', headers: { 'content-type': FORM }, body: request.body }))
        const answer = { status: response.status, body: await response.json() }
        answers.push(answer)
        return answer
    }
    const idpToken = () => {
        const nowSec = Math.floor(deps.now() / 1000)
        if (deployment === 'clerk') return signToken(keys.clerk, clerkClaims({ iat: nowSec - 10, nbf: nowSec - 20, exp: nowSec + 50 }))
        const times = { iat: nowSec - 10, nbf: nowSec - 10, exp: nowSec + 3600 }
        return signToken(keys.casdoor, casdoorClaims({ ...times, aud: [MINI_PROGRAM_CLIENT], azp: MINI_PROGRAM_CLIENT }))
    }
    return { transport, requests, answers, idpFetches: calls, send, idpToken, now: deps.now, advance }
}

// Captured before any test fakes timers: fake timers do not stop the real event loop
const realSetTimeout = globalThis.setTimeout.bind(globalThis)

// Lets real asynchronous work, such as the bridge's crypto, run until the condition holds
export async function until(condition: () => boolean): Promise<void> {
    for (let turn = 0; !condition(); turn++) {
        if (turn === 1000) throw new Error('condition never held')
        await tick()
    }
}

export function tick(): Promise<void> {
    return new Promise((resolve) => realSetTimeout(resolve, 0))
}

export async function rejection(pending: Promise<unknown>): Promise<unknown> {
    return pending.then(
        () => {
            throw new Error('expected a rejection')
        },
        (caught: unknown) => caught,
    )
}
