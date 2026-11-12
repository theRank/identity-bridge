// Keys are generated per run, so no key material is ever committed

export interface BridgeKeys {
    json: string
    active: JsonWebKey
    retired: JsonWebKey[]
}

export type RsaAlgorithm = 'RS256' | 'RS384' | 'RS512' | 'PS256'
export type EcAlgorithm = 'ES256' | 'ES384'

export interface IdpKeyPair {
    alg: RsaAlgorithm | EcAlgorithm
    kid: string
    privateKey: CryptoKey
    publicJwk: JsonWebKey & { kid: string; alg: string; use: 'sig' }
}

const EC_PUBLIC = ['kty', 'crv', 'x', 'y'] as const
const EC_PRIVATE = [...EC_PUBLIC, 'd'] as const
const RSA_PUBLIC = ['kty', 'n', 'e'] as const

const RSA: Record<RsaAlgorithm, { name: string; hash: string }> = {
    RS256: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    RS384: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
    RS512: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
    PS256: { name: 'RSA-PSS', hash: 'SHA-256' },
}

const CURVES: Record<EcAlgorithm, string> = { ES256: 'P-256', ES384: 'P-384' }

// An active EC P-256 private JWK and `retired` public ones, members limited to what the secret holds
export async function bridgeSigningKeys(retired = 0): Promise<BridgeKeys> {
    const active = await exportJwk((await generate({ name: 'ECDSA', namedCurve: 'P-256' }, true)).privateKey, EC_PRIVATE)
    const old = await Promise.all(
        Array.from({ length: retired }, async () =>
            exportJwk((await generate({ name: 'ECDSA', namedCurve: 'P-256' }, false)).publicKey, EC_PUBLIC),
        ),
    )
    return { json: JSON.stringify({ active, retired: old }), active, retired: old }
}

// modulusLength below 2048 makes a key the bridge must refuse
export async function rsaKeyPair(options: { alg?: RsaAlgorithm; kid?: string; modulusLength?: number } = {}): Promise<IdpKeyPair> {
    const { alg = 'RS256', kid = crypto.randomUUID(), modulusLength = 2048 } = options
    const pair = await generate({ ...RSA[alg], modulusLength, publicExponent: new Uint8Array([1, 0, 1]) }, false)
    return idpKeyPair(pair, alg, kid, RSA_PUBLIC)
}

export async function ecKeyPair(options: { alg?: EcAlgorithm; kid?: string } = {}): Promise<IdpKeyPair> {
    const { alg = 'ES256', kid = crypto.randomUUID() } = options
    const pair = await generate({ name: 'ECDSA', namedCurve: CURVES[alg] }, false)
    return idpKeyPair(pair, alg, kid, EC_PUBLIC)
}

export function idpJwks(...pairs: IdpKeyPair[]): { keys: IdpKeyPair['publicJwk'][] } {
    return { keys: pairs.map((pair) => pair.publicJwk) }
}

async function idpKeyPair(
    pair: CryptoKeyPair,
    alg: IdpKeyPair['alg'],
    kid: string,
    members: readonly (keyof JsonWebKey)[],
): Promise<IdpKeyPair> {
    const publicJwk = { ...(await exportJwk(pair.publicKey, members)), kid, alg, use: 'sig' as const }
    return { alg, kid, privateKey: pair.privateKey, publicJwk }
}

async function generate(algorithm: SubtleCryptoGenerateKeyAlgorithm, extractable: boolean): Promise<CryptoKeyPair> {
    return (await crypto.subtle.generateKey(algorithm, extractable, ['sign', 'verify'])) as CryptoKeyPair
}

async function exportJwk(key: CryptoKey, members: readonly (keyof JsonWebKey)[]): Promise<JsonWebKey> {
    const jwk = (await crypto.subtle.exportKey('jwk', key)) as JsonWebKey
    return Object.fromEntries(members.map((member) => [member, jwk[member]])) as unknown as JsonWebKey
}
