import { START_MS } from './deps'
import type { IdpKeyPair } from './keys'

// Seconds on the fakeDeps clock, before any advance
export const NOW_SEC = START_MS / 1000

export interface EdKeyPair extends Omit<IdpKeyPair, 'alg'> {
    alg: 'EdDSA'
}

export type SigningKeyPair = IdpKeyPair | EdKeyPair

const SIGNING: Record<SigningKeyPair['alg'], string | SubtleCryptoSignAlgorithm> = {
    RS256: 'RSASSA-PKCS1-v1_5',
    RS384: 'RSASSA-PKCS1-v1_5',
    RS512: 'RSASSA-PKCS1-v1_5',
    PS256: { name: 'RSA-PSS', saltLength: 32 },
    ES256: { name: 'ECDSA', hash: 'SHA-256' },
    ES384: { name: 'ECDSA', hash: 'SHA-384' },
    EdDSA: 'Ed25519',
}

// An Ed25519 pair for an IdP that signs EdDSA, its public JWK limited to kty, crv and x
export async function edKeyPair(options: { kid?: string } = {}): Promise<EdKeyPair> {
    const { kid = crypto.randomUUID() } = options
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])) as CryptoKeyPair
    const { x } = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey
    return { alg: 'EdDSA', kid, privateKey: pair.privateKey, publicJwk: { kty: 'OKP', crv: 'Ed25519', x: x!, kid, alg: 'EdDSA', use: 'sig' } }
}

export function base64url(data: string | Uint8Array): string {
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data
    let binary = ''
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// Signs with crypto.subtle rather than jose, so a token can carry any header and claims and be signed by a key
// jose refuses, such as RSA under 2048 bits. The header defaults to the pair's alg and kid; a member set to
// undefined is left out, as JSON.stringify drops it.
export async function signToken(pair: SigningKeyPair, claims: object, header: Record<string, unknown> = {}): Promise<string> {
    const input = `${base64url(JSON.stringify({ alg: pair.alg, typ: 'JWT', kid: pair.kid, ...header }))}.${base64url(JSON.stringify(claims))}`
    const signature = await crypto.subtle.sign(SIGNING[pair.alg], pair.privateKey, new TextEncoder().encode(input))
    return `${input}.${base64url(new Uint8Array(signature))}`
}

// A compact JWS whose signature is whatever is given, for tokens that must fail before any key is used
export function unsignedToken(header: object, claims: object, signature = ''): string {
    return `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}.${signature}`
}

// A Clerk session token: azp is the request's Origin, no aud, a 60 s lifetime with nbf a little before iat, and
// the custom session claims a deployment adds for the bridge
export function clerkClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        azp: 'https://acme.example',
        exp: NOW_SEC + 50,
        fva: [0, -1],
        iat: NOW_SEC - 10,
        iss: 'https://clerk.acme.example',
        nbf: NOW_SEC - 20,
        sid: 'sess_2abcDEFghiJKLmnoPQRstuVWXyz',
        sub: 'user_2abcDEFghiJKLmnoPQRstuVWXyz',
        v: 2,
        email: 'ada@acme.example',
        name: 'Ada Lovelace',
        picture: 'https://img.clerk.example/ada.png',
        ...overrides,
    }
}

// A Casdoor JWT-Custom access token for the acme web client, with EmailVerified, DisplayName, Avatar and
// Properties.uid selected
export function casdoorClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        owner: 'acme',
        name: 'ada',
        displayName: 'Ada Lovelace',
        avatar: 'https://cdn.casdoor.example/avatar/ada.png',
        email: 'ada@acme.example',
        emailVerified: true,
        uid: '6f1c9e2a-3b4d-4e5f-8a6b-7c8d9e0f1a2b',
        tokenType: 'access-token',
        nonce: '',
        scope: 'openid profile',
        iss: 'https://casdoor.example',
        sub: '0f5a3c1e-7b2d-4c9e-a8f6-1d2e3b4c5a6f',
        aud: ['acme-web-client'],
        exp: NOW_SEC + 3600,
        nbf: NOW_SEC - 10,
        iat: NOW_SEC - 10,
        jti: 'admin/5e8f2c4a-9b1d-4e3f-a6c7-8d9e0f1a2b3c',
        azp: 'acme-web-client',
        ...overrides,
    }
}
