// Checks a running bridge from outside, as a deployer does after every deploy. It needs no secret and no IdP token:
// each check is an answer any healthy deployment gives. Exits 1 on any mismatch.
//
//     node scripts/smoke.ts <base-url> <product-id> [--header 'name: value']...
//
// Each --header goes with every request, such as the access cookie an ESA debug domain needs. Header values are never
// printed, since they can be credentials. A header given twice is sent once with both values, a cookie's joined with
// "; " and any other's with ", ", so several cookies go in one --header, 'cookie: a=1; b=2', or in one each.
//
// Self-contained, with fetch only: Node runs this file by stripping its types, which needs import specifiers with a
// .ts extension, and src/ is not written that way.

const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
const JWT = 'urn:ietf:params:oauth:token-type:jwt'
// Product ids are lowercase, so this audience can never be configured
const UNKNOWN_AUDIENCE = 'Smoke-Test-Unknown-Product'
const TIMEOUT_MS = 10_000
// The members of a private or secret JWK (RFC 7518 section 6): a JWKS holding one has published a signing key
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']

function usage(problem?: string): never {
    process.stderr.write(`${problem ? `${problem}\n` : ''}usage: node scripts/smoke.ts <base-url> <product-id> [--header 'name: value']...\n`)
    process.exit(2)
}

const extra = new Headers()

// Headers refuses a name that is not a token and a value holding a line break. Its message is not passed on, since
// it could quote the value.
function addHeader(text: string | undefined): boolean {
    const colon = text?.indexOf(':') ?? -1
    if (text === undefined || colon < 0) return false
    try {
        extra.append(text.slice(0, colon).trim(), text.slice(colon + 1))
        return true
    } catch {
        return false
    }
}

const args: string[] = []
for (let index = 2; index < process.argv.length; index++) {
    if (process.argv[index] !== '--header') args.push(process.argv[index]!)
    else if (!addHeader(process.argv[++index])) usage("a --header must be given as 'name: value'")
}
const [base, product] = args
if (!base || !product) usage()
const root = base.replace(/\/+$/, '')

class Mismatch extends Error {}

function get(path: string): Promise<Response> {
    return fetch(`${root}${path}`, { headers: extra, signal: AbortSignal.timeout(TIMEOUT_MS) })
}

function exchange(params: Record<string, string>): Promise<Response> {
    const body = new URLSearchParams({ grant_type: TOKEN_EXCHANGE, subject_token: 'not-a-jwt', subject_token_type: JWT, audience: product!, ...params })
    const headers = new Headers(extra)
    headers.set('content-type', 'application/x-www-form-urlencoded')
    return fetch(`${root}/token`, {
        method: 'POST',
        headers,
        body,
        signal: AbortSignal.timeout(TIMEOUT_MS),
    })
}

async function body(response: Response): Promise<unknown> {
    const text = await response.text()
    try {
        return JSON.parse(text) as unknown
    } catch {
        return text
    }
}

function field(value: unknown, name: string): unknown {
    return typeof value === 'object' && value !== null ? (value as Record<string, unknown>)[name] : undefined
}

async function expectStatus(response: Response, status: number): Promise<unknown> {
    const answer = await body(response)
    if (response.status !== status) throw new Mismatch(`got ${response.status} ${JSON.stringify(answer)}`)
    return answer
}

async function expectError(response: Response, error: string): Promise<void> {
    const answer = await body(response)
    if (response.status !== 400 || field(answer, 'error') !== error) {
        throw new Mismatch(`got ${response.status} ${String(field(answer, 'error') ?? JSON.stringify(answer))}`)
    }
}

const checks: [name: string, check: () => Promise<void>][] = [
    [
        'GET /healthz is 200 ok',
        async () => {
            const answer = await expectStatus(await get('/healthz'), 200)
            if (field(answer, 'status') !== 'ok') throw new Mismatch(`got ${JSON.stringify(answer)}`)
        },
    ],
    [
        'GET /.well-known/jwks.json has an ES256 key with a kid, and no private key',
        async () => {
            // The answer is quoted only once no key in it is found to hold a private member
            const response = await get('/.well-known/jwks.json')
            const keys = field(await body(response), 'keys')
            if (response.status !== 200) throw new Mismatch(`got ${response.status}`)
            if (!Array.isArray(keys)) throw new Mismatch('got no keys array')
            const held = PRIVATE_MEMBERS.filter((member) => keys.some((key) => field(key, member) !== undefined))
            if (held.length > 0) throw new Mismatch(`a key has the private members ${held.join(', ')}`)
            const usable = keys.some((key) => field(key, 'alg') === 'ES256' && typeof field(key, 'kid') === 'string' && field(key, 'kid') !== '')
            if (!usable) throw new Mismatch(`got keys ${JSON.stringify(keys)}`)
        },
    ],
    ['POST /token with a junk subject token is 400 invalid_request', async () => expectError(await exchange({}), 'invalid_request')],
    ['POST /token for an unknown audience is 400 invalid_target', async () => expectError(await exchange({ audience: UNKNOWN_AUDIENCE }), 'invalid_target')],
    ['POST /token with another grant type is 400 unsupported_grant_type', async () => expectError(await exchange({ grant_type: 'authorization_code' }), 'unsupported_grant_type')],
    ['POST /token with a scope is 400 invalid_scope', async () => expectError(await exchange({ scope: 'openid' }), 'invalid_scope')],
    ['GET of an unknown path is 404', async () => void (await expectStatus(await get('/smoke-test-unknown-path'), 404))],
]

let failed = 0
for (const [name, check] of checks) {
    try {
        await check()
        process.stdout.write(`ok   ${name}\n`)
    } catch (error) {
        failed++
        process.stdout.write(`FAIL ${name}: ${error instanceof Error ? error.message : String(error)}\n`)
    }
}
process.stdout.write(failed === 0 ? `smoke test passed: ${root}\n` : `smoke test failed: ${failed} of ${checks.length} checks against ${root}\n`)
process.exitCode = failed === 0 ? 0 : 1
