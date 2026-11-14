import type { LifecycleEvent, WebhookSourceConfig } from '../types'

// One per source type. The route reads the raw body once, authenticates it, then parses it.
export interface WebhookAdapter {
    authenticate(request: Request, rawBody: string, secret: string, nowMs: number): Promise<boolean>
    // An empty array means the delivery is authenticated but not relayed
    parse(request: Request, rawBody: string, source: WebhookSourceConfig): LifecycleEvent[]
}

// Authenticated but unprocessable. The message is a fixed phrase and never quotes the payload.
export class BadPayloadError extends Error {
    override name = 'BadPayloadError'
}

export type JsonObject = Record<string, unknown>

export function isObject(value: unknown): value is JsonObject {
    return typeof value === 'object' && value !== null && !Array.isArray(value)
}

// Only the value's own member, so a name such as constructor never reads Object.prototype
export function own(object: JsonObject, key: string): unknown {
    return Object.hasOwn(object, key) ? object[key] : undefined
}

export function parseObject(text: string, what: string): JsonObject {
    let value: unknown
    try {
        value = JSON.parse(text)
    } catch {
        // The SyntaxError message quotes the payload
        throw new BadPayloadError(`${what} is not JSON`)
    }
    if (!isObject(value)) throw new BadPayloadError(`${what} is not a JSON object`)
    return value
}
