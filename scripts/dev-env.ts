// Prints throwaway values for running the bridge locally or in CI, never for a deployment: a test BRIDGE_CONFIG on
// .example hosts, a SIGNING_KEYS holding a key generated for this run, and a secret for its webhook source.
// One NAME=value per line, the value unquoted, as docker run --env-file, node --env-file and wrangler's .dev.vars
// read them; a shell's source would strip the quotes inside the JSON.
//
//     node scripts/dev-env.ts > dev.env

const config = {
    issuer: 'https://id.dev.example',
    idps: {
        'dev-idp': {
            issuer: 'https://idp.dev.example',
            jwksUri: 'https://idp.dev.example/.well-known/jwks.json',
        },
    },
    products: {
        acme: {
            idps: [{ idp: 'dev-idp' }],
            allowedOrigins: ['https://acme.example'],
            events: { url: 'https://api.acme.example/identity/events' },
        },
    },
    webhookSources: {
        'dev-clerk': { type: 'clerk', idp: 'dev-idp', products: ['acme'] },
    },
}

const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
const { kty, crv, x, y, d } = await crypto.subtle.exportKey('jwk', pair.privateKey)

const values = {
    BRIDGE_CONFIG: JSON.stringify(config),
    SIGNING_KEYS: JSON.stringify({ active: { kty, crv, x, y, d } }),
    // Shaped like a Clerk signing secret: whsec_ and 24 random bytes in base64
    WEBHOOK_SECRET_DEV_CLERK: `whsec_${Buffer.from(crypto.getRandomValues(new Uint8Array(24))).toString('base64')}`,
}

for (const [name, value] of Object.entries(values)) process.stdout.write(`${name}=${value}\n`)
