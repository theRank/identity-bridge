// Runs the bridge against a real Clerk instance, to catch what the fixtures cannot: a Clerk release that changes
// what its session tokens, its JWKS or its claims look like. For each case it creates a throwaway user on a
// dedicated Clerk test instance through the Backend API, mints a real session token, exchanges it at the Node
// bundle, and checks what a product would see. Exits 1 on any mismatch.
//
//     npm run build:node
//     CLERK_SECRET_KEY=sk_test_... CLERK_ISSUER=https://<instance>.clerk.accounts.dev node scripts/e2e-clerk.ts
//
// Needs a dedicated Clerk DEVELOPMENT instance: POST /v1/sessions, which mints a session without a sign-in, is
// offered only on development instances, and the script refuses an sk_live_ key. The instance must carry the
// session-token customization from docs/idp-clerk.md, the email, name, picture and uid claims; without it the
// token has no profile and the first check fails, pointing back to that step. CLERK_ISSUER is the instance's
// Frontend API URL, the `iss` of its tokens; set it directly, or let it be read from CLERK_PUBLISHABLE_KEY. The
// secret is used only as the Backend API bearer and is never logged.
//
// Only token exchange is covered. Clerk delivers webhooks asynchronously over the public internet through Svix,
// which a CI run cannot receive without standing infrastructure, so webhooks stay on the captured fixtures.

import { spawn } from 'node:child_process'
import { randomBytes, randomUUID } from 'node:crypto'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { setTimeout as sleep } from 'node:timers/promises'
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose'

type Doc = Record<string, any>

const BUNDLE = join(import.meta.dirname, '../dist/node/server.mjs')
const BRIDGE_ISSUER = 'https://id.e2e.example'
const PRODUCT = 'acme'
const IDP = 'clerk-acme'
const CLERK_API = process.env.CLERK_API_URL ?? 'https://api.clerk.com/v1'
const SECRET = process.env.CLERK_SECRET_KEY ?? ''
const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
// docs/api.md, "User ids"
const USER_ID_NAMESPACE = '95c1f512-a23b-48f7-8328-199bb33cc0b4'
// Log codes that mean the bridge could not do its job, none of which this run should produce
const BAD_CODES = ['jwks_unavailable', 'runtime_unavailable', 'internal_error']

class Mismatch extends Error {}

function expect(condition: boolean, problem: string): asserts condition {
    if (!condition) throw new Mismatch(problem)
}

const hex = (bytes: number) => randomBytes(bytes).toString('hex')

async function uuidv5(name: string, namespace: string): Promise<string> {
    const input = Buffer.concat([Buffer.from(namespace.replaceAll('-', ''), 'hex'), Buffer.from(name)])
    const hash = Buffer.from(await crypto.subtle.digest('SHA-1', input)).subarray(0, 16)
    hash[6] = (hash[6]! & 0x0f) | 0x50
    hash[8] = (hash[8]! & 0x3f) | 0x80
    const digits = hash.toString('hex')
    return [digits.slice(0, 8), digits.slice(8, 12), digits.slice(12, 16), digits.slice(16, 20), digits.slice(20)].join('-')
}

// The instance's Frontend API URL, the issuer of its session tokens. A publishable key is the base64 of that
// host with a trailing '$' (docs/idp-clerk.md derives the issuer from it the same way).
function clerkIssuer(): string {
    const direct = process.env.CLERK_ISSUER
    if (direct) return direct.replace(/\/+$/, '')
    const pk = process.env.CLERK_PUBLISHABLE_KEY
    if (pk) {
        const host = Buffer.from(pk.replace(/^pk_(test|live)_/, ''), 'base64').toString('utf8').replace(/\$+$/, '')
        if (host) return `https://${host}`
    }
    throw new Error('set CLERK_ISSUER to the instance Frontend API URL, or CLERK_PUBLISHABLE_KEY to derive it')
}

// ---------------------------------------------------------------- Clerk's Backend API

async function clerk(method: string, path: string, body?: Doc): Promise<Doc> {
    const headers: Record<string, string> = { Authorization: `Bearer ${SECRET}` }
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    const response = await fetch(`${CLERK_API}${path}`, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) })
    const text = await response.text()
    let doc: Doc = {}
    try {
        doc = text ? (JSON.parse(text) as Doc) : {}
    } catch {
        // Left as {}, reported below with the raw text
    }
    // Clerk never echoes the bearer, so the body is safe to show
    if (!response.ok) throw new Error(`${method} ${path} -> ${response.status} ${text.slice(0, 300)}`)
    return doc
}

const cleanups: (() => void | Promise<void>)[] = []

// A throwaway user on the test instance. Backend-created email addresses are verified automatically, which is
// what the mapping's "emailVerified": true trusts. The +clerk_test subaddress is Clerk's test address, accepted
// on a development instance without real delivery; a unique suffix avoids a clash with a user a crashed run left.
async function createUser(first: string, last: string, externalId?: string): Promise<Doc> {
    const user = await clerk('POST', '/users', {
        email_address: [`e2e-${first.toLowerCase()}-${hex(4)}+clerk_test@example.com`],
        // Sent for an instance that enables username; a unique value keeps it from clashing across runs
        username: `e2e_${first.toLowerCase()}_${hex(4)}`,
        first_name: first,
        last_name: last,
        skip_password_requirement: true,
        ...(externalId === undefined ? {} : { external_id: externalId }),
    })
    expect(typeof user.id === 'string', `create-user returned no id: ${JSON.stringify(user).slice(0, 300)}`)
    cleanups.push(async () => void (await clerk('DELETE', `/users/${String(user.id)}`)))
    return user
}

// The session token a client would pass to the bridge, minted without a sign-in. Returns the token and the
// Clerk user id, which is its `sub` and so what the bridge derives a user id from.
async function sessionToken(first: string, last: string, externalId?: string): Promise<{ jwt: string; userId: string }> {
    const user = await createUser(first, last, externalId)
    const session = await clerk('POST', '/sessions', { user_id: user.id })
    expect(typeof session.id === 'string', `create-session returned no id: ${JSON.stringify(session).slice(0, 300)}`)
    // An empty JSON body so Clerk sees the application/json it requires on this endpoint
    const token = await clerk('POST', `/sessions/${String(session.id)}/tokens`, {})
    expect(typeof token.jwt === 'string', `create-session-token returned no jwt: ${JSON.stringify(token).slice(0, 300)}`)
    return { jwt: token.jwt as string, userId: user.id as string }
}

// ---------------------------------------------------------------- the run

const checks: [name: string, passed: boolean, problem?: string][] = []

async function check(name: string, run: () => Promise<void>): Promise<void> {
    try {
        await run()
        checks.push([name, true])
        process.stdout.write(`ok   ${name}\n`)
    } catch (error) {
        const problem = error instanceof Error ? error.message : String(error)
        checks.push([name, false, problem])
        process.stdout.write(`FAIL ${name}: ${problem}\n`)
    }
}

const bridgeLines: string[] = []

// The bridge writes a request's line before it answers, but this process may read the answer first
async function logLine(index: number): Promise<Doc> {
    for (let attempt = 0; attempt < 40 && bridgeLines.length <= index; attempt++) await sleep(50)
    return JSON.parse(bridgeLines[index] ?? '{}') as Doc
}

async function main(): Promise<void> {
    if (!existsSync(BUNDLE)) throw new Error(`${BUNDLE} is missing: run npm run build:node first`)
    if (!SECRET) throw new Error('set CLERK_SECRET_KEY to the development instance secret key (sk_test_...)')
    if (SECRET.startsWith('sk_live_')) throw new Error('refusing to run against a production instance: use a development instance key (sk_test_...)')
    const issuer = clerkIssuer()
    process.stdout.write(`Clerk ${issuer}\n`)

    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const { kty, crv, x, y, d } = await crypto.subtle.exportKey('jwk', pair.privateKey)
    const config = {
        issuer: BRIDGE_ISSUER,
        idps: {
            [IDP]: {
                issuer,
                jwksUri: `${issuer}/.well-known/jwks.json`,
                algorithms: ['RS256'],
                claims: { uid: 'uid', email: 'email', emailVerified: true, name: 'name', picture: 'picture' },
            },
        },
        products: { [PRODUCT]: { idps: [{ idp: IDP }] } },
    }
    const bridge = spawn(process.execPath, [BUNDLE], {
        env: { BRIDGE_CONFIG: JSON.stringify(config), SIGNING_KEYS: JSON.stringify({ active: { kty, crv, x, y, d } }), HOST: '127.0.0.1', PORT: '0' },
        stdio: ['ignore', 'pipe', 'inherit'],
    })
    cleanups.push(() => void bridge.kill())
    const bridgePort = await new Promise<number>((resolve, reject) => {
        bridge.once('exit', (code) => reject(new Error(`the bridge exited with ${code}`)))
        createInterface(bridge.stdout).on('line', (line) => {
            bridgeLines.push(line)
            const entry = JSON.parse(line) as Doc
            if (entry.event === 'listening') resolve(entry.port as number)
        })
    })
    const bridgeUrl = `http://127.0.0.1:${bridgePort}`
    const health = await fetch(`${bridgeUrl}/healthz`)
    expect(health.status === 200, `the bridge's /healthz is ${health.status}`)
    const bridgeKeys = createRemoteJWKSet(new URL(`${bridgeUrl}/.well-known/jwks.json`))

    const exchange = (subjectToken: string) =>
        fetch(`${bridgeUrl}/token`, {
            method: 'POST',
            body: new URLSearchParams({ grant_type: TOKEN_EXCHANGE, subject_token: subjectToken, subject_token_type: 'urn:ietf:params:oauth:token-type:jwt', audience: PRODUCT }),
        })

    // What a product's backend checks of an access token (docs/api.md, "Verifying an access token")
    async function accessClaims(subjectToken: string): Promise<JWTPayload> {
        const response = await exchange(subjectToken)
        const answer = (await response.json()) as Doc
        expect(response.status === 200, `the exchange is ${response.status} ${JSON.stringify(answer)}`)
        const { payload } = await jwtVerify(answer.access_token as string, bridgeKeys, { issuer: BRIDGE_ISSUER, audience: PRODUCT, typ: 'at+jwt', algorithms: ['ES256'] })
        return payload
    }

    const derived = (userId: string) => uuidv5(JSON.stringify([issuer, userId]), USER_ID_NAMESPACE)

    // ------------------------------------------------------------ checks

    await check("a user exchanges their session token, for the id derived from Clerk's issuer and user id, with the mapped profile", async () => {
        const { jwt, userId } = await sessionToken('Nina', 'North')
        const claims = await accessClaims(jwt)
        const wanted = await derived(userId)
        expect(claims.sub === wanted, `sub is ${String(claims.sub)}, not ${wanted} of the Clerk user id ${userId}`)
        expect(claims.idp === IDP && claims.client_id === PRODUCT, `idp and client_id are ${String(claims.idp)} and ${String(claims.client_id)}`)
        // A missing profile almost always means the instance has no "Customize session token" claims
        expect(claims.name === 'Nina North', `name is ${String(claims.name)}: are the session-token claims set on the instance (docs/idp-clerk.md)?`)
        expect(typeof claims.email === 'string' && (claims.email as string).startsWith('e2e-nina-'), `email is ${String(claims.email)}`)
        expect(typeof claims.picture === 'string' && (claims.picture as string).startsWith('https://'), `picture is ${String(claims.picture)}`)
    })

    await check('a user with an external_id override is exchanged for that id', async () => {
        const uid = randomUUID()
        const { jwt } = await sessionToken('Olga', 'Override', uid)
        const claims = await accessClaims(jwt)
        expect(claims.sub === uid, `sub is ${String(claims.sub)}, not the override ${uid}`)
        expect(typeof claims.email === 'string' && (claims.email as string).startsWith('e2e-olga-'), `email is ${String(claims.email)}`)
    })

    await check('a user whose external_id is not a canonical UUID is refused, with no access token', async () => {
        const { jwt } = await sessionToken('Bad', 'Id', `not-a-uuid-${hex(4)}`)
        const from = bridgeLines.length
        const response = await exchange(jwt)
        const { code } = await logLine(from)
        expect(response.status === 400 && code === 'bad_uid', `the exchange got ${response.status}, logged as ${String(code)}, not bad_uid`)
    })

    await check('no exchange ended with a log code of a failure the bridge could not work around', async () => {
        const bad = bridgeLines.map((line) => (JSON.parse(line) as Doc).code as string | undefined).filter((code) => code !== undefined && BAD_CODES.includes(code))
        expect(bad.length === 0, `the log has ${bad.join(', ')}`)
    })
}

let crashed = false
try {
    await main()
} catch (error) {
    crashed = true
    process.stdout.write(`FAIL ${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`)
}
const failed = checks.filter(([, passed]) => !passed).length
if (crashed || failed > 0) process.stdout.write(`\nthe bridge's log:\n${bridgeLines.join('\n')}\n`)
for (const cleanup of cleanups.reverse()) {
    try {
        await cleanup()
    } catch {
        // A user left behind carries the e2e- prefix and can be removed from the Clerk dashboard
    }
}
process.stdout.write(crashed ? 'e2e test did not finish\n' : failed === 0 ? `e2e test passed: ${checks.length} checks against ${clerkIssuer()}\n` : `e2e test failed: ${failed} of ${checks.length} checks\n`)
process.exit(crashed || failed > 0 ? 1 : 0)
