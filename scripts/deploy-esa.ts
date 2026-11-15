// Deploys the bridge to an ESA Functions and Pages routine through the ESA OpenAPI, with the deployer's AccessKey:
//
//     node scripts/deploy-esa.ts --name <routine> --bundle <esa.js> --vars <file> [--env staging|production] [--endpoint <host>]
//                                [--print-access-token]
//
// In order, it:
// - creates the routine unless it exists;
// - sets the variables of the --vars file in the environment, BRIDGE_CONFIG as plain text and the rest as secrets,
//   and warns of bridge variables the environment holds that the file lacks, deleting none;
// - creates a code version bound to the environment, the only way the variables reach a version, uploads the bundle
//   into it and waits until it is available;
// - deploys that version to all requests and prints the routine's default domain;
// - for staging, prints the addresses staging answers on: the default domain resolves to production;
// - with --print-access-token, prints the token the default domain needs as its esa_er_token cookie.
// ESA's own CLI cannot set the variables: it refuses values over 200 characters, which a configuration or a
// rotation's SIGNING_KEYS exceed, though ESA takes them.
//
// The variables file holds NAME=value lines, as scripts/dev-env.ts prints them, for BRIDGE_CONFIG, SIGNING_KEYS and
// WEBHOOK_SECRET_* only. The AccessKey comes from ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET.
// --env defaults to production and --endpoint to esa.cn-hangzhou.aliyuncs.com. Nothing printed holds a variable's
// value or the AccessKey: an error gives the API's code and message only, and for the call that carries the values
// only its code.
//
// Self-contained, like scripts/smoke.ts, so that Node runs it by stripping its types.

import { createHash, createHmac, randomUUID } from 'node:crypto'
import { readFileSync, realpathSync } from 'node:fs'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'
import { crc32, deflateRawSync } from 'node:zlib'

const USAGE =
    'usage: node scripts/deploy-esa.ts --name <routine> --bundle <esa.js> --vars <file> [--env staging|production] ' +
    '[--endpoint <host>] [--print-access-token]'
const API_VERSION = '2024-09-10'
const ALGORITHM = 'ACS3-HMAC-SHA256'
const DEFAULT_ENDPOINT = 'esa.cn-hangzhou.aliyuncs.com'
const ENVIRONMENTS = ['staging', 'production']
// ESA's rule for routine names
const ROUTINE_NAME = /^[a-z][a-z0-9-]+$/
const HOST = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i
// A webhook secret is named for its source id in capitals, with _ for -
const BRIDGE_VARIABLE = /^(BRIDGE_CONFIG|SIGNING_KEYS|WEBHOOK_SECRET_[A-Z0-9_]+)$/
const PAGE_SIZE = 50
const MAX_PAGES = 100
// Five minutes, as long as ESA's CLI waits for a version
const WAIT_MS = 300_000
const POLL_MS = 2_000
const RETRIES = 3
const API_TIMEOUT_MS = 30_000
const UPLOAD_TIMEOUT_MS = 120_000
// The file of the code package that the routine runs
const ENTRY = 'routine/index.js'
// 1980-01-01, the earliest date a zip entry holds, so that one bundle always gives the same archive
const DOS_DATE = (1 << 5) | 1
const ARGUMENT_ERRORS: Record<string, string> = {
    ERR_PARSE_ARGS_UNKNOWN_OPTION: 'unknown option',
    ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL: 'unexpected argument',
    ERR_PARSE_ARGS_INVALID_OPTION_VALUE: 'an option with a missing or unexpected value',
}

// A message known to quote no variable value and no credential, so that it can be printed
class DeployError extends Error {}

// No answer in time, or one cut off: a failure that may pass
class Unanswered extends DeployError {}

class ApiError extends DeployError {
    readonly status: number
    readonly code: string | undefined

    constructor(message: string, status: number, code: string | undefined) {
        super(message)
        this.status = status
        this.code = code
    }
}

// What may pass on its own: no answer, a server error or throttling
function transient(error: unknown): boolean {
    if (error instanceof Unanswered) return true
    return error instanceof ApiError && (error.status >= 500 || error.status === 429 || (error.code?.startsWith('Throttling') ?? false))
}

export interface Credentials {
    accessKeyId: string
    accessKeySecret: string
}

export interface SignedRequest {
    method: string
    host: string
    query: Record<string, string>
    // The headers sent but host, which fetch sets from the URL
    headers: Record<string, string>
    body: string
}

// Signature V3: the canonical request signs host, content-type and every x-acs- header, and the hash of the body
export function authorization(request: SignedRequest, credentials: Credentials): string {
    const headers = new Map([['host', request.host]])
    for (const [name, value] of Object.entries(request.headers)) headers.set(name.toLowerCase(), value.trim())
    const signed = [...headers.keys()].filter((name) => name === 'host' || name === 'content-type' || name.startsWith('x-acs-')).sort()
    const canonical = [
        request.method,
        '/',
        canonicalQuery(request.query),
        signed.map((name) => `${name}:${headers.get(name)}\n`).join(''),
        signed.join(';'),
        sha256(request.body),
    ].join('\n')
    const signature = createHmac('sha256', credentials.accessKeySecret).update(`${ALGORITHM}\n${sha256(canonical)}`).digest('hex')
    return `${ALGORITHM} Credential=${credentials.accessKeyId},SignedHeaders=${signed.join(';')},Signature=${signature}`
}

// Sorted by name, names and values percent-encoded as RFC 3986 says, so a space is %20 and * is %2A
export function canonicalQuery(query: Record<string, string>): string {
    return Object.keys(query)
        .sort()
        .map((name) => `${percentEncode(name)}=${percentEncode(query[name]!)}`)
        .join('&')
}

function percentEncode(text: string): string {
    return encodeURIComponent(text).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
}

function sha256(data: string | Uint8Array): string {
    return createHash('sha256').update(data).digest('hex')
}

// A zip archive of one deflated file
export function zip(name: string, data: Uint8Array): Buffer {
    const path = Buffer.from(name)
    const compressed = deflateRawSync(data)
    // What a local header and its central directory entry share: version 2.0 to extract, no flags, deflate, a time of
    // 00:00, the date, the CRC, both sizes and the length of the name, with no extra field
    const entry = Buffer.alloc(26)
    entry.writeUInt16LE(20, 0)
    entry.writeUInt16LE(8, 4)
    entry.writeUInt16LE(DOS_DATE, 8)
    entry.writeUInt32LE(crc32(data), 10)
    entry.writeUInt32LE(compressed.length, 14)
    entry.writeUInt32LE(data.length, 18)
    entry.writeUInt16LE(path.length, 22)
    const local = Buffer.alloc(30 + path.length)
    local.writeUInt32LE(0x04034b50, 0)
    entry.copy(local, 4)
    path.copy(local, 30)
    // Made by version 2.0, then no comment, disk 0, no attributes, and the local header at offset 0
    const central = Buffer.alloc(46 + path.length)
    central.writeUInt32LE(0x02014b50, 0)
    central.writeUInt16LE(20, 4)
    entry.copy(central, 6)
    path.copy(central, 46)
    const end = Buffer.alloc(22)
    end.writeUInt32LE(0x06054b50, 0)
    end.writeUInt16LE(1, 8)
    end.writeUInt16LE(1, 10)
    end.writeUInt32LE(central.length, 12)
    end.writeUInt32LE(local.length + compressed.length, 16)
    return Buffer.concat([local, compressed, central, end])
}

// NAME=value lines, read much as docker run --env-file reads them: blank lines, the spaces before a name, a byte
// order mark among them, and lines starting with # are skipped, and the value is everything after the first =, quotes
// and all, so a JSON value needs no escaping. A refused line is named by its number alone, since a secret pasted on a
// line of its own can look like NAME=value; only a bridge variable's name, which is no secret, is quoted.
export function parseVarsFile(text: string): Map<string, string> {
    const variables = new Map<string, string>()
    for (const [index, raw] of text.split('\n').entries()) {
        // trimStart counts U+FEFF as a space, so it also drops a byte order mark
        const line = (raw.endsWith('\r') ? raw.slice(0, -1) : raw).trimStart()
        if (line === '' || line.startsWith('#')) continue
        const at = line.indexOf('=')
        const name = line.slice(0, Math.max(at, 0))
        const where = `line ${index + 1}`
        if (at < 0 || !BRIDGE_VARIABLE.test(name)) throw new DeployError(`${where}: not BRIDGE_CONFIG, SIGNING_KEYS or a WEBHOOK_SECRET_ name`)
        if (variables.has(name)) throw new DeployError(`${where}: ${name} is set twice`)
        if (at === line.length - 1) throw new DeployError(`${where}: ${name} is empty`)
        variables.set(name, line.slice(at + 1))
    }
    if (variables.size === 0) throw new DeployError('it sets no variable')
    return variables
}

export interface Io {
    fetch(url: string, init: RequestInit): Promise<Response>
    // Where the AccessKey is read from
    env: Record<string, string | undefined>
    stdout(text: string): void
    stderr(text: string): void
    sleep(ms: number): Promise<void>
    // A signal that aborts after ms, as AbortSignal.timeout gives
    timeout(ms: number): AbortSignal
    // In ms, as Date.now gives
    now(): number
}

interface Options {
    name: string
    bundle: string
    vars: string
    env: string
    endpoint: string
    printAccessToken: boolean
}

// 0 once deployed, 1 when a step fails, 2 for a usage error
export async function main(args: string[], io: Io): Promise<number> {
    let options: Options
    try {
        options = parseOptions(args)
    } catch (error) {
        io.stderr(`${error instanceof DeployError ? error.message : 'invalid arguments'}\n${USAGE}\n`)
        return 2
    }
    const accessKeyId = io.env.ALIBABA_CLOUD_ACCESS_KEY_ID
    const accessKeySecret = io.env.ALIBABA_CLOUD_ACCESS_KEY_SECRET
    if (!accessKeyId || !accessKeySecret) {
        io.stderr('ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET must hold the AccessKey to deploy with\n')
        return 2
    }
    try {
        return await deploy(options, { accessKeyId, accessKeySecret }, io)
    } catch (error) {
        // Any other message, such as a JSON parser's, can quote the text it failed on
        io.stderr(`error: ${error instanceof DeployError ? error.message : `unexpected ${error instanceof Error ? error.name : 'error'}`}\n`)
        return 1
    }
}

// The arguments hold no secret, but a fixed message stays safe if one is passed by mistake
function parseOptions(args: string[]): Options {
    let values: { name?: string; bundle?: string; vars?: string; env?: string; endpoint?: string; 'print-access-token'?: boolean }
    try {
        const string = { type: 'string' } as const
        const options = { name: string, bundle: string, vars: string, env: string, endpoint: string, 'print-access-token': { type: 'boolean' } } as const
        values = parseArgs({ args, options }).values
    } catch (error) {
        throw new DeployError(ARGUMENT_ERRORS[(error as { code?: string }).code ?? ''] ?? 'invalid arguments')
    }
    const { name, bundle, vars, env = 'production', endpoint = DEFAULT_ENDPOINT, 'print-access-token': printAccessToken = false } = values
    if (name === undefined || bundle === undefined || vars === undefined) throw new DeployError('--name, --bundle and --vars are required')
    if (!ROUTINE_NAME.test(name)) throw new DeployError('--name takes lowercase letters, digits and -, starting with a letter, at least 2 characters')
    if (!ENVIRONMENTS.includes(env)) throw new DeployError('--env is staging or production')
    if (!HOST.test(endpoint)) throw new DeployError(`--endpoint is a host name, such as ${DEFAULT_ENDPOINT}`)
    return { name, bundle, vars, env, endpoint, printAccessToken }
}

// 0, or 1 when the deploy is done but the access token asked for could not be read
async function deploy(options: Options, credentials: Credentials, io: Io): Promise<number> {
    const { name, env } = options
    // Both files first, so that a mistake in either stops the deploy before it changes anything
    const variables = readVarsFile(options.vars)
    const bundle = read(options.bundle, 'the bundle')
    const api = client(options.endpoint, credentials, io)

    let routine = await getRoutine(api, name)
    if (routine === undefined) await api({ action: 'CreateRoutine', method: 'POST', query: { Name: name, Description: 'identity-bridge' } })
    io.stdout(`routine ${name}: ${routine === undefined ? 'created' : 'exists'}\n`)

    await setVariables(api, name, env, variables)
    io.stdout(`${env} variables set: ${[...variables.keys()].map((key) => `${key} (${variableType(key)})`).join(', ')}\n`)
    for (const key of await listVariables(api, io, name, env)) {
        if (BRIDGE_VARIABLE.test(key) && !variables.has(key)) io.stderr(`warning: ${env} holds ${key}, which ${options.vars} does not set; it is kept\n`)
    }

    const version = await createVersion(api, io, name, env, bundle)
    io.stdout(`code version ${version}: uploaded\n`)
    await waitUntilAvailable(api, io, name, version)
    io.stdout(`code version ${version}: available\n`)

    const versions = JSON.stringify([{ Percentage: 100, CodeVersion: version }])
    await api({ action: 'CreateRoutineCodeDeployment', method: 'POST', query: { Name: name, Env: env, Strategy: 'percentage', CodeVersions: versions } })
    io.stdout(`${env}: code version ${version} deployed to 100 percent of requests\n`)

    // A routine just created is read again for its domain
    routine ??= await getRoutine(api, name)
    const domain = text(routine?.DefaultRelatedRecord)
    io.stdout(domain === undefined ? 'the routine has no default domain\n' : `default domain: https://${domain}\n`)

    const host = domain ?? '<domain>'
    const staging = env === 'staging' ? await printStagingAddresses(api, io, host) : undefined
    return options.printAccessToken && !(await printAccessToken(api, io, name, host, staging)) ? 1 : 0
}

// The default domain resolves to production, so staging answers only on its own addresses. They only help reach a
// deploy that is done, so a failure to read them is a warning.
async function printStagingAddresses(api: Api, io: Io, domain: string): Promise<string[]> {
    let answer: Answer
    try {
        answer = await api({ action: 'GetRoutineStagingEnvIp', method: 'GET' })
    } catch (error) {
        if (!(error instanceof DeployError)) throw error
        io.stderr(`warning: the staging addresses could not be read: ${error.message}\n`)
        return []
    }
    const addresses = Array.isArray(answer.IPV4) ? answer.IPV4.filter((address): address is string => typeof address === 'string' && address !== '') : []
    if (addresses.length === 0) {
        io.stderr('warning: ESA gave no staging address\n')
        return []
    }
    io.stdout(`staging addresses: ${addresses.join(', ')}\n`)
    io.stdout(
        `note: the default domain resolves to production; staging answers only on these addresses, as with ` +
            `curl --resolve ${domain}:443:${addresses[0]} https://${domain}/healthz\n`,
    )
    return addresses
}

// Only on request: the token opens the default domain to whoever holds it. It goes on a line of its own and never
// into a command, which a quote in it would break. For staging, given its addresses, the smoke test, which has no
// --resolve, needs the domain pointed at one of them first.
async function printAccessToken(api: Api, io: Io, name: string, domain: string, staging: string[] | undefined): Promise<boolean> {
    let token: string | undefined
    try {
        const answer = await api({ action: 'GetRoutineAccessToken', method: 'GET', query: { Name: name } })
        token = typeof answer.Token === 'string' && answer.Token !== '' ? answer.Token : undefined
        if (token === undefined) throw new DeployError('GetRoutineAccessToken: the answer has no Token')
    } catch (error) {
        if (!(error instanceof DeployError)) throw error
        io.stderr(`deployed, but the access token could not be read: ${error.message}\n`)
        return false
    }
    io.stdout(`access token: ${token}\n`)
    io.stdout('note: the default domain answers only with the token as its esa_er_token cookie\n')
    if (staging !== undefined) {
        io.stdout(
            `note: the smoke test reaches staging only once ${domain} points at a staging address, ` +
                `for example through this line in the hosts file: ${staging[0] ?? '<address>'} ${domain}\n`,
        )
    }
    io.stdout(`smoke test: node scripts/smoke.ts https://${domain} <product-id> --header 'cookie: esa_er_token=<token>'\n`)
    return true
}

function read(path: string, what: string): Buffer {
    try {
        return readFileSync(path)
    } catch (error) {
        throw new DeployError(`cannot read ${what} ${path}: ${(error as NodeJS.ErrnoException).code ?? 'unknown error'}`)
    }
}

function readVarsFile(path: string): Map<string, string> {
    const text = read(path, 'the variables file').toString('utf8')
    try {
        return parseVarsFile(text)
    } catch (error) {
        throw error instanceof DeployError ? new DeployError(`${path}: ${error.message}`) : error
    }
}

async function getRoutine(api: Api, name: string): Promise<Answer | undefined> {
    try {
        return await api({ action: 'GetRoutine', method: 'GET', query: { Name: name } })
    } catch (error) {
        if (error instanceof ApiError && error.code === 'RoutineNotExist') return undefined
        throw error
    }
}

function variableType(name: string): string {
    return name === 'BRIDGE_CONFIG' ? 'plain_text' : 'secret_text'
}

async function setVariables(api: Api, name: string, env: string, variables: Map<string, string>): Promise<void> {
    const values = JSON.stringify(Object.fromEntries([...variables].map(([key, value]) => [key, { Type: variableType(key), Value: value }])))
    try {
        await api({
            action: 'SetRoutineEnvironmentVariables',
            method: 'POST',
            form: { Name: name, Env: env, EnvironmentVariables: values },
            carriesValues: true,
        })
    } catch (error) {
        if (error instanceof ApiError && error.code === '400019') {
            throw new DeployError(`${error.message}: over ESA's variable quota, which counts names and values together, 16,384 characters on the free plan`)
        }
        throw error
    }
}

// The names only, since the answer holds the plain values in clear. A page can hold fewer names than asked for, so
// the pages run to TotalCount when ESA gives it, and otherwise to a page that adds no name. That also ends the list
// for a server that gives the same page again.
async function listVariables(api: Api, io: Io, name: string, env: string): Promise<Set<string>> {
    const names = new Set<string>()
    for (let page = 1; page <= MAX_PAGES; page++) {
        const answer = await api({
            action: 'ListRoutineEnvironmentVariables',
            method: 'POST',
            form: { Name: name, Env: env, PageNumber: String(page), PageSize: String(PAGE_SIZE) },
        })
        if (!isRecord(answer.EnvironmentVariables)) {
            // Past the first page, how an empty last page can come
            if (page > 1) return names
            io.stderr(`warning: ESA listed the ${env} variables without their names, so the check for stale variables was skipped\n`)
            return names
        }
        const before = names.size
        for (const key of Object.keys(answer.EnvironmentVariables)) names.add(key)
        const total = typeof answer.TotalCount === 'number' ? answer.TotalCount : undefined
        if (names.size === before || (total !== undefined && names.size >= total)) return names
    }
    io.stderr(`warning: listing the ${env} variables stopped after ${MAX_PAGES} pages, so the check for stale variables may have missed some\n`)
    return names
}

// A version created with DeployEnv takes that environment's variables. ESA answers with a form for OSS's
// PostObject, which reads its fields before the file.
async function createVersion(api: Api, io: Io, name: string, env: string, bundle: Buffer): Promise<string> {
    const answer = await api({
        action: 'CreateRoutineWithAssetsCodeVersion',
        method: 'POST',
        form: { Name: name, CodeDescription: `identity-bridge ${sha256(bundle).slice(0, 12)}`, DeployEnv: env },
    })
    // Text only: as a number, a version of 19 digits would lose its last ones to JSON.parse
    const version = typeof answer.CodeVersion === 'string' && answer.CodeVersion !== '' ? answer.CodeVersion : undefined
    if (version === undefined) throw new DeployError('CreateRoutineWithAssetsCodeVersion: the answer has no CodeVersion as text')
    const oss = isRecord(answer.OssPostConfig) ? answer.OssPostConfig : {}
    const [url, accessKeyId, signature, policy, key] = ['Url', 'OSSAccessKeyId', 'Signature', 'Policy', 'Key'].map((field) => text(oss[field]))
    // Over plain HTTP, the form's signature and security token would travel in clear
    if (!url || !/^https:\/\//i.test(url) || !accessKeyId || !signature || !policy || !key) {
        throw new DeployError('CreateRoutineWithAssetsCodeVersion: the answer has no upload form over HTTPS')
    }
    const form = new FormData()
    form.append('OSSAccessKeyId', accessKeyId)
    form.append('Signature', signature)
    const token = text(oss.XOssSecurityToken)
    if (token !== undefined) form.append('x-oss-security-token', token)
    form.append('policy', policy)
    form.append('key', key)
    form.append('file', new Blob([zip(ENTRY, bundle)]), 'code.zip')
    let response: Response
    try {
        // A redirect followed would send the form's signature and token wherever it points
        response = await io.fetch(url, { method: 'POST', body: form, redirect: 'error', signal: io.timeout(UPLOAD_TIMEOUT_MS) })
    } catch (error) {
        throw new Unanswered(`OSS upload: no answer${timedOut(error) ? ` within ${UPLOAD_TIMEOUT_MS / 1000} s` : ''}`)
    }
    if (!response.ok) {
        // OSS answers an error in XML
        const answer = await response.text().catch(() => '')
        const field = (tag: string) => new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(answer)?.[1] ?? 'none'
        throw new DeployError(`OSS upload: HTTP ${response.status} ${field('Code')}: ${field('Message')}`)
    }
    return version
}

// A version is Init until its upload is unpacked, then Available. Any other status is a failed build, as ESA's CLI
// reads it. A check that fails in a way that may pass is tried again, up to RETRIES times in a row. The wait is
// bounded by the time spent, the checks' own included, rather than by their number.
async function waitUntilAvailable(api: Api, io: Io, name: string, version: string): Promise<void> {
    const start = io.now()
    let failures = 0
    for (let check = 1; ; check++) {
        if (check > 1) {
            const waited = io.now() - start
            if (waited >= WAIT_MS) throw new DeployError(`code version ${version} is not available after ${Math.round(waited / 1000)} s`)
            await io.sleep(POLL_MS)
        }
        let answer: Answer
        try {
            answer = await api({ action: 'GetRoutineCodeVersionInfo', method: 'GET', query: { Name: name, CodeVersion: version } })
        } catch (error) {
            if (!transient(error) || ++failures > RETRIES) throw error
            continue
        }
        failures = 0
        const status = text(answer.Status)
        if (status?.toLowerCase() === 'available') return
        if (status?.toLowerCase() !== 'init') throw new DeployError(`code version ${version} is ${status ?? 'without a status'}`)
    }
}

interface Call {
    action: string
    method: 'GET' | 'POST'
    query?: Record<string, string>
    form?: Record<string, string>
    // The form holds variable values, which an error's message could echo, so an error gives only its code
    carriesValues?: boolean
}

type Answer = Record<string, unknown>
type Api = (call: Call) => Promise<Answer>

// The ESA OpenAPI, in RPC style: parameters in the query or a form body, and a JSON answer that names its error
function client(host: string, credentials: Credentials, io: Io): Api {
    return async ({ action, method, query = {}, form, carriesValues = false }) => {
        const body = form === undefined ? '' : new URLSearchParams(form).toString()
        const headers: Record<string, string> = {
            'x-acs-action': action,
            'x-acs-version': API_VERSION,
            'x-acs-date': new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
            'x-acs-signature-nonce': randomUUID(),
            'x-acs-content-sha256': sha256(body),
        }
        if (form !== undefined) headers['content-type'] = 'application/x-www-form-urlencoded'
        headers.authorization = authorization({ method, host, query, headers, body }, credentials)
        const search = canonicalQuery(query)
        const url = `https://${host}/${search === '' ? '' : `?${search}`}`
        // The error is never quoted: its message or cause could name anything about the request. A redirect is not
        // followed, since that would resend the signed request wherever it points.
        let response: Response
        let raw: string
        try {
            const init: RequestInit = { method, headers, redirect: 'error', signal: io.timeout(API_TIMEOUT_MS) }
            response = await io.fetch(url, form === undefined ? init : { ...init, body })
        } catch (error) {
            throw new Unanswered(`${action}: no answer from ${host}${timedOut(error) ? ` within ${API_TIMEOUT_MS / 1000} s` : ''}`)
        }
        try {
            raw = await response.text()
        } catch {
            throw new Unanswered(`${action}: the answer could not be read`)
        }
        const answer = parseAnswer(raw)
        const status = `${action}: HTTP ${response.status}`
        if (answer === undefined) throw new ApiError(`${status}, an answer that is not JSON`, response.status, undefined)
        if (response.ok) return answer
        const code = text(answer.Code)
        const message = carriesValues ? undefined : text(answer.Message)
        throw new ApiError(`${status} ${code ?? 'without a code'}${message === undefined ? '' : `: ${message}`}`, response.status, code)
    }
}

function timedOut(error: unknown): boolean {
    return error instanceof DOMException && error.name === 'TimeoutError'
}

function parseAnswer(body: string): Answer | undefined {
    try {
        const answer = JSON.parse(body) as unknown
        return isRecord(answer) ? answer : undefined
    } catch {
        return undefined
    }
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function text(value: unknown): string | undefined {
    if (typeof value === 'number') return String(value)
    return typeof value === 'string' && value !== '' ? value : undefined
}

// Not import.meta.main, which Node 24.0 and 24.1 lack: there the script would do nothing and exit 0
function isMain(): boolean {
    try {
        return process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
    } catch {
        return false
    }
}

if (isMain()) {
    process.exitCode = await main(process.argv.slice(2), {
        fetch: (url, init) => fetch(url, init),
        env: process.env,
        stdout: (text) => void process.stdout.write(text),
        stderr: (text) => void process.stderr.write(text),
        sleep: (ms) => sleep(ms),
        timeout: (ms) => AbortSignal.timeout(ms),
        now: () => Date.now(),
    })
}
