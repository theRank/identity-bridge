// Checks tokens, webhooks and user write permissions against a throwaway Casdoor container and the Node bundle.
// Setup follows docs/idp-casdoor.md; exits 1 on mismatch.
//
//     npm run build:node
//     node scripts/e2e-casdoor.ts [image]
//
// Needs docker and openssl. The image defaults to the Casdoor version the docs were checked against.
//
// The bridge requires HTTPS: serve Casdoor's JWKS and the product's event receiver with a temporary certificate
// trusted by the bridge, and set Casdoor's origin to that HTTPS address.
//
// A built-in webhook can reach local addresses and receives all organizations, exercising tenant filtering.

import { execFileSync, spawn } from 'node:child_process'
import { randomBytes, randomUUID } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer as createHttpsServer, type Server } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { setTimeout as sleep } from 'node:timers/promises'
import { createRemoteJWKSet, decodeJwt, jwtVerify, type JWTPayload } from 'jose'

type Doc = Record<string, any>

const IMAGE = process.argv[2] ?? 'casbin/casdoor-all-in-one:4.29.0'
const BUNDLE = join(import.meta.dirname, '../dist/node/server.mjs')
const CONTAINER = `identity-bridge-e2e-${randomBytes(4).toString('hex')}`
const BRIDGE_ISSUER = 'https://id.e2e.example'
const SOURCE = 'casdoor-acme'
const ADMIN_PASSWORD = 'E2e-Admin-123'
const USER_PASSWORD = 'E2e-Pass-123'
const SMS = 'provider_sms_mock'
const AVATAR = 'https://img.acme.example/olga.png'
const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
const EVENT = 'urn:identity-bridge:event:'
// Sign-up records fall between this and the end of the run, by Casdoor's clock, which is the host's
const RUN_STARTED = Math.floor(Date.now() / 1000)
// docs/api.md, "User ids"
const USER_ID_NAMESPACE = '95c1f512-a23b-48f7-8328-199bb33cc0b4'
// Log codes that no request of this run may end with: each means the bridge and Casdoor disagree
const BAD_CODES = ['bad_payload', 'bad_uid', 'bad_webhook_auth', 'delivery_failed', 'jwks_unavailable', 'runtime_unavailable', 'internal_error']

class Mismatch extends Error {}

function expect(condition: boolean, problem: string): asserts condition {
    if (!condition) throw new Mismatch(problem)
}

const hex = (bytes: number) => randomBytes(bytes).toString('hex')
const now = () => new Date().toISOString()

async function uuidv5(name: string, namespace: string): Promise<string> {
    const input = Buffer.concat([Buffer.from(namespace.replaceAll('-', ''), 'hex'), Buffer.from(name)])
    const hash = Buffer.from(await crypto.subtle.digest('SHA-1', input)).subarray(0, 16)
    hash[6] = (hash[6]! & 0x0f) | 0x50
    hash[8] = (hash[8]! & 0x3f) | 0x80
    const digits = hash.toString('hex')
    return [digits.slice(0, 8), digits.slice(8, 12), digits.slice(12, 16), digits.slice(16, 20), digits.slice(20)].join('-')
}

function docker(...args: string[]): string {
    return execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
}

function listen(server: Server): Promise<number> {
    return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)))
}

// ---------------------------------------------------------------- Casdoor's API

let casdoorUrl = ''

interface Call {
    json?: unknown
    form?: Record<string, string>
    query?: Record<string, string>
}

// One Casdoor session, kept by its cookies
class Session {
    readonly cookies = new Map<string, string>()

    async request(method: string, path: string, { json, form, query }: Call = {}): Promise<Doc> {
        const url = new URL(path, casdoorUrl)
        for (const [name, value] of Object.entries(query ?? {})) url.searchParams.set(name, value)
        const headers: Record<string, string> = { 'Accept-Language': 'en' }
        let body: string | undefined
        if (json !== undefined) {
            body = JSON.stringify(json)
            headers['Content-Type'] = 'application/json'
        } else if (form) {
            body = new URLSearchParams(form).toString()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        }
        if (this.cookies.size) headers.Cookie = [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ')
        const response = await fetch(url, { method, headers, redirect: 'manual', ...(body === undefined ? {} : { body }) })
        for (const cookie of response.headers.getSetCookie()) {
            const pair = cookie.split(';')[0]!
            const at = pair.indexOf('=')
            this.cookies.set(pair.slice(0, at), pair.slice(at + 1))
        }
        const text = await response.text()
        try {
            return JSON.parse(text) as Doc
        } catch {
            return { status: 'error', msg: `${response.status} ${text.slice(0, 200)}` }
        }
    }

    get(path: string, query?: Record<string, string>): Promise<Doc> {
        return this.request('GET', path, query ? { query } : {})
    }

    post(path: string, call: Call): Promise<Doc> {
        return this.request('POST', path, call)
    }
}

// Casdoor answers 200 whatever happened: the outcome is the body's status
function ok(answer: Doc, what: string): Doc {
    if (answer.status !== 'ok') throw new Error(`${what}: ${JSON.stringify(answer).slice(0, 400)}`)
    return answer
}

const outcome = (answer: Doc) => (answer.status === 'ok' ? 'ok' : `refused (${String(answer.msg)})`)

async function login(organization: string, username: string, password: string): Promise<Session> {
    const session = new Session()
    const application = organization === 'built-in' ? 'app-built-in' : `app-${organization}`
    ok(await session.post('/api/login', { json: { application, organization, username, password, type: 'login', autoSignin: true, signinMethod: 'Password' } }), `login ${organization}/${username}`)
    return session
}

async function casdoorHealthy(): Promise<void> {
    for (let attempt = 0; attempt < 120; attempt++) {
        try {
            const response = await fetch(new URL('/api/health', casdoorUrl), { signal: AbortSignal.timeout(2000) })
            if (response.ok && ((await response.json()) as Doc).status === 'ok') return
        } catch {
            // Not listening yet
        }
        await sleep(1000)
    }
    throw new Error('Casdoor did not become healthy')
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

const cleanups: (() => void)[] = []
const bridgeLines: string[] = []

// The bridge writes a request's line before it answers, but this process may read the answer first
async function logLine(index: number): Promise<Doc> {
    for (let attempt = 0; attempt < 40 && bridgeLines.length <= index; attempt++) await sleep(50)
    return JSON.parse(bridgeLines[index] ?? '{}') as Doc
}

async function main(): Promise<void> {
    if (!existsSync(BUNDLE)) throw new Error(`${BUNDLE} is missing: run npm run build:node first`)

    const dir = mkdtempSync(join(tmpdir(), 'identity-bridge-e2e-'))
    cleanups.push(() => rmSync(dir, { recursive: true, force: true }))
    const certFile = join(dir, 'cert.pem')
    const keyFile = join(dir, 'key.pem')
    execFileSync(
        'openssl',
        ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=identity-bridge-e2e', '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', keyFile, '-out', certFile],
        { stdio: 'ignore' },
    )
    const tls = { key: readFileSync(keyFile), cert: readFileSync(certFile) }

    // Casdoor's key set, which is all the bridge asks an IdP for, at the address of the issuer
    const keySet = createHttpsServer(tls, (incoming, outgoing) => {
        if (incoming.url !== '/.well-known/jwks') return void outgoing.writeHead(404).end()
        fetch(new URL('/.well-known/jwks', casdoorUrl)).then(
            async (answer) => outgoing.writeHead(answer.status, { 'content-type': 'application/json' }).end(await answer.text()),
            () => outgoing.writeHead(502).end(),
        )
    })
    const idpIssuer = `https://127.0.0.1:${await listen(keySet)}`
    cleanups.push(() => void keySet.close())

    // The product's event receiver
    const received: string[] = []
    const receiver = createHttpsServer(tls, (incoming, outgoing) => {
        const chunks: Buffer[] = []
        incoming.on('data', (chunk: Buffer) => chunks.push(chunk))
        incoming.on('end', () => {
            received.push(Buffer.concat(chunks).toString())
            outgoing.writeHead(202).end()
        })
    })
    const eventsUrl = `https://127.0.0.1:${await listen(receiver)}/identity/events`
    cleanups.push(() => void receiver.close())

    process.stdout.write(`starting ${IMAGE}\n`)
    docker('run', '--detach', '--name', CONTAINER, '--publish', '127.0.0.1::8000', '--add-host', 'host.docker.internal:host-gateway', '--env', `origin=${idpIssuer}`, IMAGE)
    cleanups.push(() => void docker('rm', '--force', CONTAINER))
    const published = () => `http://${docker('port', CONTAINER, '8000/tcp').split('\n')[0]!}`
    casdoorUrl = published()

    // The bridge, listening where the container reaches the host: Docker Desktop forwards to the loopback address,
    // while on Linux the host is the gateway of Docker's bridge network
    const bridgeHost = process.platform === 'linux' ? docker('network', 'inspect', 'bridge', '--format', '{{(index .IPAM.Config 0).Gateway}}') : '127.0.0.1'
    const clientId = hex(10)
    const clientSecret = hex(20)
    const webhookSecret = hex(32)
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const { kty, crv, x, y, d } = await crypto.subtle.exportKey('jwk', pair.privateKey)
    const config = {
        issuer: BRIDGE_ISSUER,
        idps: {
            casdoor: {
                issuer: idpIssuer,
                jwksUri: `${idpIssuer}/.well-known/jwks`,
                algorithms: ['RS256'],
                requiredClaims: { tokenType: 'access-token' },
                claims: { uid: 'uid', emailVerified: 'emailVerified', name: 'displayName', picture: 'avatar', phone: 'phone', phoneRegion: 'countryCode', phoneVerified: true, updatedAt: 'iat' },
            },
        },
        products: { acme: { idps: [{ idp: 'casdoor', clientIds: [clientId] }], events: { url: eventsUrl } } },
        webhookSources: { [SOURCE]: { type: 'casdoor', idp: 'casdoor', organization: 'acme', uidField: 'uid', products: ['acme'] } },
    }
    const bridge = spawn(process.execPath, [BUNDLE], {
        env: {
            BRIDGE_CONFIG: JSON.stringify(config),
            SIGNING_KEYS: JSON.stringify({ active: { kty, crv, x, y, d } }),
            WEBHOOK_SECRET_CASDOOR_ACME: webhookSecret,
            HOST: bridgeHost,
            PORT: '0',
            NODE_EXTRA_CA_CERTS: certFile,
        },
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
    const bridgeUrl = `http://${bridgeHost}:${bridgePort}`
    const health = await fetch(`${bridgeUrl}/healthz`)
    expect(health.status === 200, `the bridge's /healthz is ${health.status}`)
    const bridgeKeys = createRemoteJWKSet(new URL(`${bridgeUrl}/.well-known/jwks.json`))

    const exchange = (subjectToken: string) =>
        fetch(`${bridgeUrl}/token`, {
            method: 'POST',
            body: new URLSearchParams({ grant_type: TOKEN_EXCHANGE, subject_token: subjectToken, subject_token_type: 'urn:ietf:params:oauth:token-type:jwt', audience: 'acme' }),
        })

    // What a product's backend checks of an access token (docs/api.md, "Verifying an access token")
    async function accessClaims(subjectToken: string): Promise<JWTPayload> {
        const response = await exchange(subjectToken)
        const answer = (await response.json()) as Doc
        expect(response.status === 200, `the exchange is ${response.status} ${JSON.stringify(answer)}`)
        const { payload } = await jwtVerify(answer.access_token as string, bridgeKeys, { issuer: BRIDGE_ISSUER, audience: 'acme', typ: 'at+jwt', algorithms: ['ES256'] })
        return payload
    }

    // ------------------------------------------------------------ Casdoor, as docs/idp-casdoor.md sets it up

    await casdoorHealthy()
    if ((await new Session().get('/api/get-init-admin-status')).data === true) {
        ok(await new Session().post('/api/init-admin-password', { form: { password: ADMIN_PASSWORD } }), 'set the admin password')
    }
    let admin = await login('built-in', 'admin', ADMIN_PASSWORD)
    process.stdout.write(`Casdoor ${JSON.stringify((await admin.get('/api/get-version-info')).data ?? null)}\n`)
    const builtIn = ok(await admin.get('/api/get-organization', { id: 'admin/built-in' }), 'get built-in').data as Doc
    const builtInApp = ok(await admin.get('/api/get-application', { id: 'admin/app-built-in' }), 'get app-built-in').data as Doc

    ok(
        await admin.post('/api/add-provider', {
            json: { owner: 'admin', name: SMS, createdTime: now(), displayName: 'Mock SMS', category: 'SMS', type: 'Mock SMS', clientId: 'x', clientSecret: 'x', signName: 'x', templateCode: 'x' },
        }),
        'add the SMS provider',
    )
    for (const name of ['acme', 'globex']) {
        // The account items are those of built-in, where Properties and Country code take an admin to change
        ok(
            await admin.post('/api/add-organization', {
                json: {
                    owner: 'admin', name, createdTime: now(), displayName: name, websiteUrl: `https://${name}.example`, favicon: builtIn.favicon,
                    passwordType: 'bcrypt', passwordOptions: ['AtLeast6'], countryCodes: ['CN', 'US', 'IT'], defaultAvatar: builtIn.defaultAvatar,
                    defaultApplication: `app-${name}`, tags: [], languages: builtIn.languages, initScore: 0, enableSoftDeletion: false, isProfilePublic: false,
                    accountItems: builtIn.accountItems, mfaItems: builtIn.mfaItems ?? [],
                },
            }),
            `add the organization ${name}`,
        )
        const acme = name === 'acme'
        ok(
            await admin.post('/api/add-application', {
                json: {
                    owner: 'admin', name: `app-${name}`, organization: name, createdTime: now(), displayName: `app-${name}`, category: 'Default', type: 'All', scopes: [],
                    logo: builtInApp.logo, enablePassword: true, enableSignUp: true, disableSignin: false, cert: 'cert-built-in',
                    clientId: acme ? clientId : hex(10), clientSecret: acme ? clientSecret : hex(20),
                    redirectUris: ['http://localhost/callback'], grantTypes: ['authorization_code', 'password', 'refresh_token'],
                    tokenFormat: 'JWT-Custom', tokenFields: ['Email', 'EmailVerified', 'DisplayName', 'Avatar', 'Phone', 'CountryCode', 'Properties.uid'],
                    expireInHours: 168, refreshExpireInHours: 168, cookieExpireInHours: 720, formOffset: 2, signinMethods: builtInApp.signinMethods,
                    providers: [{ owner: '', name: SMS, canSignUp: false, canSignIn: false, canUnlink: false, prompted: false, signupGroup: '', rule: 'All' }],
                    // No email provider in the container, so an address cannot be verified, and stays unverified
                    signupItems: [
                        { name: 'ID', visible: false, required: true, rule: 'Random' },
                        { name: 'Username', visible: true, required: true, rule: 'None' },
                        { name: 'Display name', visible: true, required: true, rule: 'None' },
                        { name: 'Password', visible: true, required: true, rule: 'None' },
                        { name: 'Confirm password', visible: true, required: true, rule: 'None' },
                        { name: 'Email', visible: true, required: false, rule: 'No verification' },
                        { name: 'Phone', visible: true, required: false, rule: 'None' },
                        { name: 'Signup button', visible: true, required: true, rule: 'None' },
                    ],
                },
            }),
            `add the application app-${name}`,
        )
    }
    ok(
        await admin.post('/api/add-webhook', {
            json: {
                owner: 'admin', name: 'webhook-bridge', createdTime: now(), organization: 'built-in', url: `http://host.docker.internal:${bridgePort}/webhooks/${SOURCE}`,
                method: 'POST', contentType: 'application/json', headers: [{ name: 'Authorization', value: `Bearer ${webhookSecret}` }],
                events: ['new-user', 'delete-user'], tokenFields: [], objectFields: ['All'], isUserExtended: true, singleOrgOnly: false, isEnabled: true,
            },
        }),
        'add the webhook',
    )
    // Casdoor starts its delivery worker at boot, and only when a webhook exists
    docker('restart', CONTAINER)
    casdoorUrl = published()
    await casdoorHealthy()
    admin = await login('built-in', 'admin', ADMIN_PASSWORD)

    const stored = async (name: string) => ok(await admin.get('/api/get-user', { id: `acme/${name}` }), `get acme/${name}`).data as Doc
    const addUser = async (name: string, extra: Doc = {}) => {
        ok(
            await admin.post('/api/add-user', {
                json: { owner: 'acme', name, createdTime: now(), type: 'normal-user', password: USER_PASSWORD, displayName: name, signupApplication: 'app-acme', ...extra },
            }),
            `add acme/${name}`,
        )
        return stored(name)
    }
    const signup = (organization: string, username: string, extra: Doc = {}) =>
        new Session().post('/api/signup', {
            json: { application: `app-${organization}`, organization, username, name: `${username} signed up`, password: USER_PASSWORD, confirm: USER_PASSWORD, agreement: true, ...extra },
        })
    const tokens = async (username: string) => {
        const answer = await new Session().post('/api/login/oauth/access_token', {
            form: { grant_type: 'password', client_id: clientId, client_secret: clientSecret, username, password: USER_PASSWORD, scope: 'openid profile' },
        })
        expect(typeof answer.access_token === 'string', `no access token for ${username}: ${JSON.stringify(answer).slice(0, 300)}`)
        return answer
    }
    const derived = (id: string) => uuidv5(JSON.stringify([idpIssuer, id]), USER_ID_NAMESPACE)
    // As Casdoor's console deletes: the whole row of the user list
    const deleteRow = async (session: Session, name: string) => {
        const rows = ok(await session.get('/api/get-users', { owner: 'acme', p: '1', pageSize: '100' }), 'get the users of acme').data as Doc[]
        const row = rows.find((user) => user.name === name)
        expect(row !== undefined, `acme/${name} is not in the user list`)
        ok(await session.post('/api/delete-user', { json: row }), `delete acme/${name}`)
    }

    const olgaUid = randomUUID()
    await addUser('acme-admin', { isAdmin: true })
    await addUser('olga', {
        displayName: 'Olga Override', email: 'olga@acme.example', emailVerified: true, avatar: AVATAR, phone: '13800138000', countryCode: 'CN', properties: { uid: olgaUid },
    })
    const quinn = await addUser('quinn')
    await addUser('pete')
    const acmeAdmin = await login('acme', 'acme-admin', USER_PASSWORD)
    // The user events expected at the product, as "<event> <sub>"
    const expected: string[] = []

    // ------------------------------------------------------------ tokens

    let ninaSub = ''
    let ninaTokenTime = 0
    await check('a user who signed up exchanges their token, for the id derived from Casdoor\'s issuer and user id', async () => {
        ok(await signup('acme', 'nina', { email: 'nina@acme.example' }), 'sign up acme/nina')
        const nina = await stored('nina')
        const casdoorToken = (await tokens('nina')).access_token as string
        const claims = await accessClaims(casdoorToken)
        // "updatedAt": "iat": the profile time is when Casdoor issued the token
        const iat = decodeJwt(casdoorToken).iat
        expect(claims.updated_at === iat, `updated_at is ${String(claims.updated_at)}, not the Casdoor token's iat ${String(iat)}`)
        ninaTokenTime = iat!
        const wanted = await derived(nina.id as string)
        expect(claims.sub === wanted, `sub is ${claims.sub}, not ${wanted} of the user id ${String(nina.id)}`)
        expect(claims.idp === 'casdoor' && claims.client_id === 'acme', `idp and client_id are ${String(claims.idp)} and ${String(claims.client_id)}`)
        expect(claims.name === 'nina signed up', `name is ${String(claims.name)}`)
        expect(claims.email === undefined, `an address Casdoor did not verify was issued: ${String(claims.email)}`)
        expect(claims.phone_number === undefined, `a phone number was issued: ${String(claims.phone_number)}`)
        ninaSub = claims.sub
        expected.push(`user-created ${ninaSub}`)
    })

    await check('only an access token is exchanged, not the refresh token or the ID token beside it', async () => {
        const answer = await tokens('nina')
        for (const kind of ['refresh_token', 'id_token']) {
            expect(typeof answer[kind] === 'string', `Casdoor gave no ${kind}`)
            const from = bridgeLines.length
            const response = await exchange(answer[kind] as string)
            const { code } = await logLine(from)
            expect(response.status === 400 && code === 'claim_mismatch', `the ${kind} got ${response.status}, logged as ${String(code)}`)
        }
    })

    await check('a user with a uid override, a verified email and a phone gets them in the access token', async () => {
        const claims = await accessClaims((await tokens('olga')).access_token as string)
        expect(claims.sub === olgaUid, `sub is ${claims.sub}, not the override ${olgaUid}`)
        const { email, phone_number, name, picture } = claims
        const profile = JSON.stringify({ email, phone_number, name, picture })
        const wanted = JSON.stringify({ email: 'olga@acme.example', phone_number: '+8613800138000', name: 'Olga Override', picture: AVATAR })
        expect(profile === wanted, `the profile is ${profile}, not ${wanted}`)
    })

    // ------------------------------------------------------------ what users cannot write, on which the override and
    // "phoneVerified": true rest

    const olga = await login('acme', 'olga', USER_PASSWORD)
    const updateSelf = async (change: Doc) => {
        const own = ok(await olga.get('/api/get-user', { id: 'acme/olga' }), 'get own user').data as Doc
        return olga.post('/api/update-user', { query: { id: 'acme/olga' }, json: { ...own, ...change } })
    }

    await check('a user cannot change their own uid override', async () => {
        const answer = await updateSelf({ properties: { uid: randomUUID() } })
        const after = (await stored('olga')).properties as Doc | null
        expect(after?.uid === olgaUid, `${outcome(answer)}, and the stored override is ${String(after?.uid)}`)
    })

    await check('a user cannot change their own phone number or its region through update-user', async () => {
        const answers = [await updateSelf({ phone: '13900139000' }), await updateSelf({ countryCode: 'US' })]
        const after = await stored('olga')
        expect(after.phone === '13800138000' && after.countryCode === 'CN', `${answers.map(outcome).join(', ')}, and the stored number is ${String(after.countryCode)} ${String(after.phone)}`)
    })

    await check('a user cannot take a phone number without the code sent to it', async () => {
        const reset = await olga.post('/api/reset-email-or-phone', { form: { type: 'phone', dest: '13900139000', countryCode: 'CN', code: '000000' } })
        const after = await stored('olga')
        expect(reset.status !== 'ok' && after.phone === '13800138000', `a change with a wrong code is ${outcome(reset)}, and the stored number is ${String(after.phone)}`)
        const refused = await signup('acme', 'nocode', { phone: '2087654321', countryCode: 'US', phoneCode: '' })
        expect(refused.status !== 'ok', 'a sign-up with a phone and no code is accepted')
    })

    await check('an administrator\'s number with a leading zero is stored without it', async () => {
        const zero = await addUser('zero', { phone: '0212345678', countryCode: 'IT' })
        expect(zero.phone === '212345678', `0212345678 is stored as ${String(zero.phone)}: docs/idp-casdoor.md and src/phone.ts assume the zero is dropped`)
    })

    await check('a user who signed up with a phone and its code gets the number, joined with its region', async () => {
        ok(
            await new Session().post('/api/send-verification-code', {
                form: { applicationId: 'admin/app-acme', method: 'signup', type: 'phone', dest: '2087654321', countryCode: 'US', captchaType: 'none', checkUser: '' },
            }),
            'send the sign-up code',
        )
        const codes = ok(await admin.get('/api/get-verifications', { owner: 'acme' }), 'get the codes').data as Doc[]
        const code = codes.find((record) => record.receiver === '+12087654321' && !record.isUsed)
        expect(code !== undefined, `no code for +12087654321 among ${codes.map((record) => String(record.receiver)).join(', ')}`)
        ok(await signup('acme', 'rita', { phone: '2087654321', countryCode: 'US', phoneCode: code.code }), 'sign up acme/rita')
        const claims = await accessClaims((await tokens('rita')).access_token as string)
        expect(claims.phone_number === '+12087654321', `phone_number is ${String(claims.phone_number)}`)
        expected.push(`user-created ${claims.sub} +12087654321`)
    })

    // ------------------------------------------------------------ webhooks

    // None of these may reach the product: another organization's user, a user's own deletion naming another
    // user, and a global admin's deletion, whose record belongs to built-in
    ok(await signup('globex', 'gina'), 'sign up globex/gina')
    const quinnSession = await login('acme', 'quinn', USER_PASSWORD)
    ok(await quinnSession.post('/api/delete-user', { json: { ...quinn, id: (await stored('olga')).id, properties: { uid: olgaUid } } }), 'acme/quinn deletes themselves')
    await deleteRow(admin, 'pete')

    await deleteRow(acmeAdmin, 'olga')
    expected.push(`user-deleted ${olgaUid}`)
    await deleteRow(acmeAdmin, 'nina')
    expected.push(`user-deleted ${ninaSub}`)

    // Two sign-ups in acme, one in globex, and four deletions. Casdoor's worker delivers every 30 seconds.
    const RECORDS = 7
    let deliveries: Doc[] = []
    for (let attempt = 0; attempt < 36; attempt++) {
        await sleep(5000)
        deliveries = (ok(await admin.get('/api/get-webhook-events', { owner: 'admin', p: '1', pageSize: '500' }), 'get the webhook deliveries').data as Doc[] | null) ?? []
        if (deliveries.length >= RECORDS && deliveries.every((delivery) => delivery.state !== 'Pending' && delivery.state !== 'Retrying')) break
    }

    await check('Casdoor delivered every webhook, and the bridge accepted each', async () => {
        const states = deliveries.map((delivery) => String(delivery.state))
        expect(states.length === RECORDS && states.every((state) => state === 'Success'), `the deliveries are ${JSON.stringify(states)}`)
    })

    await check('the product received an event for each sign-up and each deletion by its admin, with the ids of the tokens', async () => {
        const events: string[] = []
        for (const token of received) {
            const { payload } = await jwtVerify(token, bridgeKeys, { issuer: BRIDGE_ISSUER, audience: 'acme', typ: 'secevent+jwt', algorithms: ['ES256'] })
            const [[type, profile] = ['', {}]] = Object.entries((payload.events ?? {}) as Record<string, Doc>)
            events.push([type.replace(EVENT, ''), payload.sub, profile.phone_number].filter(Boolean).join(' '))
        }
        expect(JSON.stringify(events.sort()) === JSON.stringify(expected.sort()), `the events are ${JSON.stringify(events)}, not ${JSON.stringify(expected)}`)
    })

    await check('a sign-up event carries the record time in whole seconds, no later than the user\'s tokens; a deletion none', async () => {
        for (const token of received) {
            const { payload } = await jwtVerify(token, bridgeKeys, { issuer: BRIDGE_ISSUER, audience: 'acme', typ: 'secevent+jwt', algorithms: ['ES256'] })
            const [[type, profile] = ['', {}]] = Object.entries((payload.events ?? {}) as Record<string, Doc>)
            const time = profile.updated_at
            if (type.endsWith('user-deleted')) {
                expect(time === undefined, `a deletion carries updated_at ${String(time)}`)
                continue
            }
            expect(Number.isInteger(time) && (time as number) >= RUN_STARTED - 60 && (time as number) <= Date.now() / 1000 + 60, `${type} has updated_at ${String(time)}`)
            if (payload.sub === ninaSub) expect((time as number) <= ninaTokenTime, `nina's sign-up at ${String(time)} is later than her token at ${ninaTokenTime}`)
        }
    })

    await check('the bridge relayed four webhooks and ignored three, and no request ended with a log code of a disagreement', async () => {
        const lines = bridgeLines.map((line) => JSON.parse(line) as Doc)
        const bad = lines.map((line) => line.code as string | undefined).filter((code) => code !== undefined && BAD_CODES.includes(code))
        expect(bad.length === 0, `the log has ${bad.join(', ')}`)
        const webhooks = lines.filter((line) => line.route === 'webhook')
        const relayed = webhooks.filter((line) => line.delivered === 1).length
        const ignored = webhooks.filter((line) => line.code === 'ignored').length
        expect(relayed === 4 && ignored === 3, `${relayed} webhooks were relayed and ${ignored} ignored, of ${webhooks.length}`)
        const untimed = lines.filter((line) => line.updatedAt !== undefined)
        expect(untimed.length === 0, `requests without a usable time: ${JSON.stringify(untimed)}`)
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
if (crashed || failed > 0) {
    process.stdout.write(`\nthe bridge's log:\n${bridgeLines.join('\n')}\n`)
    try {
        process.stdout.write(`\nCasdoor's log, its end:\n${execFileSync('docker', ['logs', '--tail', '40', CONTAINER], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })}\n`)
    } catch {
        // The container never started
    }
}
for (const cleanup of cleanups.reverse()) {
    try {
        cleanup()
    } catch {
        // Whatever is left is the container, named above
    }
}
process.stdout.write(crashed ? 'e2e test did not finish\n' : failed === 0 ? `e2e test passed: ${checks.length} checks against ${IMAGE}\n` : `e2e test failed: ${failed} of ${checks.length} checks against ${IMAGE}\n`)
process.exit(crashed || failed > 0 ? 1 : 0)
