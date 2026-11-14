import { createServer, ServerResponse, type IncomingMessage, type Server } from 'node:http'
import type { Socket } from 'node:net'
import { Readable } from 'node:stream'
import { handle } from '../app'
import type { Deps, LogLine, Runtime, RuntimeFailure } from '../types'
import { loadRuntime, webhookSecretName } from './load'

// The router reads only the path, so the origin is fixed rather than taken from Host, which the client controls
const BASE = 'http://bridge.invalid'

// Fetch refuses to build a Request with these methods. Under a method no route allows, the router answers them as
// it answers any other wrong method: 405 with Allow on a known path, 404 elsewhere.
const REFUSED_METHODS = ['CONNECT', 'TRACE', 'TRACK']
const UNSUPPORTED_METHOD = 'X-UNSUPPORTED'

const TIMEOUTS = {
    headersTimeout: 10_000,
    // Bounds only receiving the request, not producing the answer
    requestTimeout: 30_000,
    // Above the idle timeouts of common proxies, so the proxy closes an idle connection first
    keepAliveTimeout: 65_000,
    // Node checks the two request timeouts only this often, 30 s by default
    connectionsCheckingInterval: 1_000,
}

export interface NodeServerOptions {
    env: Record<string, string | undefined>
    deps?: Partial<Deps>
    // One line of JSON, written to stdout unless given
    log?(text: string): void
}

export interface NodeServer {
    server: Server
    // Settles once the runtime has loaded or failed to; requests that arrive before wait for it
    ready: Promise<void>
}

// The runtime is loaded once, when the server is created, and the bundle creates one server per process
export function createNodeServer(options: NodeServerOptions): NodeServer {
    const log = options.log ?? ((text: string) => void process.stdout.write(`${text}\n`))
    const deps: Deps = {
        fetch: (input, init) => fetch(input, init),
        now: () => Date.now(),
        randomUUID: () => crypto.randomUUID(),
        log: (line) => log(JSON.stringify(line)),
        ...options.deps,
    }
    const runtime = load(options.env, log)
    // A failure writing an answer drops that connection rather than the process
    const server = createServer(TIMEOUTS, (req, res) => void serve(req, res, server, runtime, deps).catch(() => res.destroy()))
    // Node hands a CONNECT request over as a bare socket, which it would otherwise destroy unanswered
    server.on('connect', (req: IncomingMessage, socket: Socket) => {
        const res = new ServerResponse(req)
        res.assignSocket(socket)
        res.shouldKeepAlive = false
        res.on('finish', () => socket.end())
        void serve(req, res, server, runtime, deps).catch(() => socket.destroy())
    })
    return { server, ready: runtime.then(() => {}) }
}

async function load(env: NodeServerOptions['env'], log: (text: string) => void): Promise<Runtime | RuntimeFailure> {
    const runtime = await loadRuntime({
        config: env.BRIDGE_CONFIG,
        signingKeys: env.SIGNING_KEYS,
        webhookSecret: (sourceId) => env[webhookSecretName(sourceId)],
    })
    if ('reason' in runtime) log(JSON.stringify({ event: 'runtime_load_failed', reason: runtime.reason }))
    return runtime
}

async function serve(req: IncomingMessage, res: ServerResponse, server: Server, runtime: Promise<Runtime | RuntimeFailure>, deps: Deps): Promise<void> {
    const start = deps.now()
    // The core logs once per request; the line is held, so it can say the connection ended early
    let line: LogLine | undefined
    const requestDeps: Deps = {
        ...deps,
        log: (entry) => {
            line = entry
        },
    }
    let response: Response
    let body: Uint8Array
    try {
        response = await handle(toRequest(req), await runtime, requestDeps)
        body = new Uint8Array(await response.arrayBuffer())
    } catch {
        // Never logged: the error may quote the request
        line = { route: 'other', status: 500, ms: deps.now() - start, outcome: 'error', code: 'internal_error' }
        response = new Response(null, { status: 500 })
        body = new Uint8Array()
    }
    // The client went away, or Node's request timeout fired, before the request was read: whatever the core made
    // of the missing bytes, no one receives its answer
    if (line && !req.complete && res.destroyed) line = { ...line, status: 499, outcome: 'rejected', code: 'client_closed' }
    if (line) deps.log(line)
    res.statusCode = response.status
    for (const [name, value] of response.headers) res.appendHeader(name, value)
    // A body left unread is not drained, so a client cannot keep sending past the limit; and once shutting
    // down, a connection closes with its last answer rather than waiting to go idle
    if (!req.complete || !server.listening) res.setHeader('connection', 'close')
    res.end(body)
}

// The core's readBody enforces its byte limit on the stream as it reads, so the body is never buffered here
function toRequest(req: IncomingMessage): Request {
    const refused = REFUSED_METHODS.includes((req.method ?? '').toUpperCase())
    const method = refused ? UNSUPPORTED_METHOD : (req.method ?? 'GET')
    const headers = new Headers()
    for (let index = 0; index + 1 < req.rawHeaders.length; index += 2) headers.append(req.rawHeaders[index]!, req.rawHeaders[index + 1]!)
    const init: RequestInit & { duplex?: 'half' } = { method, headers }
    if (method !== 'GET' && method !== 'HEAD' && !refused) {
        // The same Web stream, though Node's types and the Workers' describe it differently
        init.body = Readable.toWeb(req) as unknown as ReadableStream
        init.duplex = 'half'
    }
    return new Request(requestUrl(req.url ?? '/'), init)
}

// An origin-form target keeps its path as sent, so //a/b stays a path; an absolute-form one, which names a host
// of the client's choosing, keeps only its path and query. A target URL cannot parse gets the path /, which no
// route serves.
function requestUrl(target: string): URL {
    const url = new URL(BASE)
    try {
        const { pathname, search } = target.startsWith('/') ? new URL(`${BASE}${target}`) : new URL(target, BASE)
        url.pathname = pathname
        url.search = search
    } catch {
        url.pathname = '/'
    }
    return url
}

// Stops accepting connections and closes idle ones; each request in flight is answered, and its connection
// closes with the answer. Resolves once every connection has closed, or when the deadline passes, closing the
// connections left.
export function shutdown(server: Server, deadline: Promise<unknown>): Promise<void> {
    return new Promise((resolve) => {
        server.close(() => resolve())
        void deadline.then(() => server.closeAllConnections())
    })
}
