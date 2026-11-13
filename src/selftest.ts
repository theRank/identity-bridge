import { base64url, generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose'

// Generated once; the private key was never stored. jose refuses RSA keys under 2048 bits, so this one has 2048.
const RS256_KEY = {
    kty: 'RSA',
    n:
        '1_J8lF9_LvLDz8zazH-vo85KM9NoElsvOIU7jD6pviKEkplLqZYIB7e8YvZCZgB7VdI-JZwaR9hJzFh7ZjhvBZzu5owlSjGcg34XSFIOylEAi4YctDpBYaBd' +
        'zCprpYxxsHIcEhp0bccydo5F0zeHBQdGcWiO8QwHyVt6y1XXjb5QFCHQu5R4no-3VRfKc2UZg5y7ITNiaCZ5it1qYxtgl9wTdFJTW3tF337f9aqu7uSENVCam' +
        'ZBkuIYydrYsWajTM5mjCkCQ4OuQanZdHwKy1WCHPJF0wVXNj3K2yReFr3pIxmOZ85CYQQxi5roY7nxqPQphySlvY8woO4Dvsh3AvQ',
    e: 'AQAB',
}
const RS256_TOKEN =
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpZGVudGl0eS1icmlkZ2UiLCJzdWIiOiJzZWxmLXRlc3QifQ.' +
    'w_w3YVtVGG_9QplW6OfgZQFmIAFhdg8J2WxIn5qhQ6EFE322bBDIlC6CUy-xiTJNYimYX6BK0wzaTZtgzPxHPeOBt4ulru9Ijr1vxMjtG_d1fHWcjpzwquVXq_' +
    'MU5o1dXkDo7gFr0Wb_0zxR2e504rU90GtBEKj6uZUvArvhFxaBC1gayW8rtIllGy6aMjTusIG3P00ipLmQUmRMuAIF4ZvVOatuHb7a9Dsprn1b7FAbzJLde6cqj' +
    '9QIbw0JO8LhA8DCu-5yeN7fEfDKExMrmzpG3vUEhSAEjlaKHGPdz46Jhh-xVkANDimi0PhotXqXMBJ8_w0F_2wIUylSnALhJg'
const SHA1_ABC = 'a9993e364706816aba3e25717850c26c9cd0d89d'
// RFC 4231 test case 2
const HMAC_KEY = 'Jefe'
const HMAC_DATA = 'what do ya want for nothing?'
const HMAC_SHA256 = '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'

let result: Promise<boolean> | undefined

// Once per isolate. Resolves false on any failure and never rejects.
export function cryptoSelfTest(): Promise<boolean> {
    result ??= run()
    return result
}

async function run(): Promise<boolean> {
    try {
        const checks = await Promise.all([es256(), rs256(), sha1(), hmacSha256()])
        return checks.every((passed) => passed)
    } catch {
        return false
    }
}

async function es256(): Promise<boolean> {
    const { privateKey, publicKey } = await generateKeyPair('ES256')
    const token = await new SignJWT({ sub: 'self-test' }).setProtectedHeader({ alg: 'ES256' }).sign(privateKey)
    return verifies(token, publicKey, 'ES256')
}

async function rs256(): Promise<boolean> {
    return verifies(RS256_TOKEN, await importJWK(RS256_KEY, 'RS256'), 'RS256')
}

// The tampered copy must fail too, or a verify that accepts anything would pass
async function verifies(token: string, key: CryptoKey | Uint8Array, alg: string): Promise<boolean> {
    const { payload } = await jwtVerify(token, key, { algorithms: [alg] })
    const [header, , signature] = token.split('.')
    const tampered = `${header}.${base64url.encode(JSON.stringify({ sub: 'tampered' }))}.${signature}`
    const rejected = await jwtVerify(tampered, key, { algorithms: [alg] }).then(
        () => false,
        () => true,
    )
    return payload.sub === 'self-test' && rejected
}

async function sha1(): Promise<boolean> {
    return hex(await crypto.subtle.digest('SHA-1', encode('abc'))) === SHA1_ABC
}

async function hmacSha256(): Promise<boolean> {
    const key = await crypto.subtle.importKey('raw', encode(HMAC_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    return hex(await crypto.subtle.sign('HMAC', key, encode(HMAC_DATA))) === HMAC_SHA256
}

function encode(text: string): Uint8Array {
    return new TextEncoder().encode(text)
}

function hex(buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, '0')).join('')
}
