import { empty, json, oauthError } from './http'
import { healthRoute } from './routes/health'
import { jwksRoute } from './routes/jwks'
import { tokenRoute } from './routes/token'
import { webhooksRoute } from './routes/webhooks'
import type { Deps, LogCode, LogLine, RouteContext, RouteHandler, Runtime, RuntimeFailure } from './types'

export interface Routes {
    token: RouteHandler
    jwks: RouteHandler
    health: RouteHandler
    webhooks: RouteHandler
}

type Route = Exclude<LogLine['route'], 'other'>

interface Match {
    route: Route
    methods: string[]
    handler: RouteHandler
    ctx: RouteContext
}

interface Answer {
    route: LogLine['route']
    response: Response
    ctx: RouteContext
}

const WEBHOOKS = '/webhooks/'

const ROUTES: Routes = { token: tokenRoute, jwks: jwksRoute, health: healthRoute, webhooks: webhooksRoute }

export function handle(request: Request, runtime: Runtime | RuntimeFailure, deps: Deps): Promise<Response> {
    return dispatch(request, runtime, deps, ROUTES)
}

// handle with the route handlers passed in, so tests can substitute them
export async function dispatch(request: Request, runtime: Runtime | RuntimeFailure, deps: Deps, routes: Routes): Promise<Response> {
    const start = deps.now()
    const { route, response, ctx } = await answer(request, runtime, deps, routes)
    deps.log({ route, status: response.status, ms: deps.now() - start, outcome: outcome(response.status), ...ctx })
    return response
}

// 404 and 405 come before the runtime check, so they are the same in failure mode
async function answer(request: Request, runtime: Runtime | RuntimeFailure, deps: Deps, routes: Routes): Promise<Answer> {
    const found = match(new URL(request.url).pathname, routes)
    if (!found) return { route: 'other', response: empty(404), ctx: {} }
    const { route, methods, handler, ctx } = found
    if (!methods.includes(request.method)) return { route, response: empty(405, { allow: methods.join(', ') }), ctx }
    if ('reason' in runtime) return failureResponse(route, ctx, 'runtime_unavailable')
    try {
        return { route, response: await handler(request, runtime, deps, ctx), ctx }
    } catch {
        // Never logged: the error may quote a token or a payload
        return failureResponse(route, ctx, 'internal_error')
    }
}

function match(path: string, routes: Routes): Match | undefined {
    if (path === '/token') return { route: 'token', methods: ['POST', 'OPTIONS'], handler: routes.token, ctx: {} }
    if (path === '/.well-known/jwks.json') return { route: 'jwks', methods: ['GET'], handler: routes.jwks, ctx: {} }
    if (path === '/healthz') return { route: 'health', methods: ['GET'], handler: routes.health, ctx: {} }
    // {source} is exactly one non-empty segment, compared literally: neither decoded nor case-folded
    const source = path.startsWith(WEBHOOKS) ? path.slice(WEBHOOKS.length) : ''
    if (source !== '' && !source.includes('/')) return { route: 'webhook', methods: ['POST'], handler: routes.webhooks, ctx: { source } }
    return undefined
}

function failureResponse(route: Route, ctx: RouteContext, code: LogCode): Answer {
    ctx.code = code
    if (route === 'health') return { route, response: json(503, { status: 'unavailable' }, { 'cache-control': 'no-store' }), ctx }
    if (route === 'token') return { route, response: oauthError(500, 'server_error', code), ctx }
    return { route, response: empty(500), ctx }
}

function outcome(status: number): LogLine['outcome'] {
    if (status >= 500) return 'error'
    if (status >= 400) return 'rejected'
    return 'ok'
}
