import { empty, json, readBody } from '../http'
import { BadUidError, deriveUserId, eventId } from '../ids'
import { mintEventToken } from '../tokens'
import type { Config, Deps, LifecycleEvent, LogCode, RouteContext, RouteHandler, Runtime, WebhookSourceConfig } from '../types'
import { BadPayloadError, type WebhookAdapter } from '../webhooks/adapter'
import { casdoor } from '../webhooks/casdoor'
import { clerk } from '../webhooks/clerk'

const MAX_BODY_BYTES = 262144
const DELIVERY_TIMEOUT_MS = 5000
const ADAPTERS: Record<WebhookSourceConfig['type'], WebhookAdapter> = { clerk, casdoor }
const DELIVERY_HEADERS = { 'content-type': 'application/secevent+jwt', accept: 'application/json' }

type DeliveryError = 'timeout' | 'network' | `status ${number}`

interface Target {
    product: string
    url: string
}

interface Delivery extends Target {
    token: string
}

interface Failure {
    product: string
    error: DeliveryError
}

export const webhooksRoute: RouteHandler = async (request, runtime, deps, ctx) => {
    const source = ctx.source === undefined ? undefined : runtime.config.webhookSources[ctx.source]
    if (source === undefined) return refuse(ctx, 404, 'unknown_source')
    ctx.idp = source.idp
    // Read as text before parsing: the Svix signature covers the exact bytes
    const body = await readBody(request, MAX_BODY_BYTES)
    if (body === null) return refuse(ctx, 413, 'too_large')
    const adapter = ADAPTERS[source.type]
    if (!(await adapter.authenticate(request, body, runtime.webhookSecret(source.id), deps.now()))) return refuse(ctx, 401, 'bad_webhook_auth')

    // The IdP would redeliver the same bytes, so an unprocessable payload is answered 200 and the log code is the alert
    let events: LifecycleEvent[]
    try {
        events = adapter.parse(request, body, source)
    } catch (error) {
        if (!(error instanceof BadPayloadError)) throw error
        return answer(ctx, [], [], 'bad_payload')
    }
    if (events.length === 0) return answer(ctx, [], [], 'ignored')

    const issuer = runtime.config.idps[source.idp]?.issuer
    if (issuer === undefined) throw new Error('webhook source names an unknown idp')
    let userIds: string[]
    try {
        userIds = await Promise.all(events.map((event) => deriveUserId(issuer, event.subject, event.uid)))
    } catch (error) {
        if (!(error instanceof BadUidError)) throw error
        return answer(ctx, [], [], 'bad_uid')
    }

    const deliveries = await mint(events, userIds, source, runtime, Math.floor(deps.now() / 1000))
    const errors = await Promise.all(deliveries.map((delivery) => deliver(deps.fetch, delivery)))
    const delivered: string[] = []
    const failed: Failure[] = []
    deliveries.forEach(({ product }, index) => {
        const error = errors[index]
        if (error === undefined) delivered.push(product)
        else failed.push({ product, error })
    })
    return answer(ctx, delivered, failed, failed.length === 0 ? undefined : 'delivery_failed')
}

// Sign all tokens before sending, so signing failures cannot cause a partial fan-out.
async function mint(events: LifecycleEvent[], userIds: string[], source: WebhookSourceConfig, runtime: Runtime, nowSec: number): Promise<Delivery[]> {
    const targets = source.products.map((product) => target(runtime.config, product))
    const deliveries: Delivery[] = []
    for (const [index, event] of events.entries()) {
        const { idpEventId, type, profile } = event
        const tokenEvent = { jti: await eventId(source.id, idpEventId), txn: idpEventId, userId: userIds[index]!, type, profile }
        for (const { product, url } of targets) {
            deliveries.push({ product, url, token: await mintEventToken(runtime.keys, runtime.config, product, tokenEvent, nowSec) })
        }
    }
    return deliveries
}

function target(config: Config, product: string): Target {
    const url = config.products[product]?.events?.url
    if (url === undefined) throw new Error('webhook source names a product without events')
    return { product, url }
}

// The timer ends the wait on its own, since not every runtime has AbortController or a fetch that honours a
// signal; where one exists, it also cancels the request. Redirects are failures, so none is followed.
function deliver(fetch: Deps['fetch'], { url, token }: Delivery): Promise<DeliveryError | undefined> {
    const controller = typeof AbortController === 'function' ? new AbortController() : undefined
    const init: RequestInit = { method: 'POST', headers: DELIVERY_HEADERS, body: token, redirect: 'manual' }
    if (controller) init.signal = controller.signal
    return new Promise((resolve) => {
        const timer = setTimeout(() => {
            resolve('timeout')
            controller?.abort()
        }, DELIVERY_TIMEOUT_MS)
        post(fetch, url, init)
            .then(resolve, () => resolve('network'))
            .finally(() => clearTimeout(timer))
    })
}

async function post(fetch: Deps['fetch'], url: string, init: RequestInit): Promise<DeliveryError | undefined> {
    let response: Response
    try {
        response = await fetch(url, init)
    } catch {
        return 'network'
    }
    // Releases the connection: the answer's content is never read
    await response.body?.cancel().catch(() => {})
    return response.status >= 200 && response.status < 300 ? undefined : `status ${response.status}`
}

function refuse(ctx: RouteContext, status: number, code: LogCode): Response {
    ctx.code = code
    return empty(status)
}

function answer(ctx: RouteContext, delivered: string[], failed: Failure[], code: LogCode | undefined): Response {
    if (code !== undefined) ctx.code = code
    ctx.delivered = delivered.length
    ctx.failed = failed.length
    return json(failed.length === 0 ? 200 : 502, { delivered, failed })
}
