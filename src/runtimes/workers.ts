import { handle } from '../app'
import type { Deps, Runtime, RuntimeFailure } from '../types'
import { loadRuntime, webhookSecretName } from './load'

// Declared here rather than generated: each deployment names its own webhook sources, so their secrets cannot be
// declared in this repository
export interface Env {
    BRIDGE_CONFIG?: string | undefined
    SIGNING_KEYS?: string | undefined
    [secret: `WEBHOOK_SECRET_${string}`]: string | undefined
}

// Wrapped, because Workers methods detached from their object throw Illegal invocation
const deps: Deps = {
    fetch: (input, init) => fetch(input, init),
    now: () => Date.now(),
    randomUUID: () => crypto.randomUUID(),
    log: (line) => console.log(JSON.stringify(line)),
}

// Keyed by env, one object for the life of an isolate. The IdP key sets are cached by the parsed configuration and
// keep the fetch they were first given, so the runtime must live as long as the isolate rather than a request.
const runtimes = new WeakMap<Env, Promise<Runtime | RuntimeFailure>>()

function runtimeFor(env: Env): Promise<Runtime | RuntimeFailure> {
    let runtime = runtimes.get(env)
    if (runtime === undefined) {
        runtime = load(env)
        runtimes.set(env, runtime)
    }
    return runtime
}

async function load(env: Env): Promise<Runtime | RuntimeFailure> {
    const runtime = await loadRuntime({
        config: env.BRIDGE_CONFIG,
        signingKeys: env.SIGNING_KEYS,
        webhookSecret: (sourceId) => env[webhookSecretName(sourceId)],
    })
    if ('reason' in runtime) console.log(JSON.stringify({ event: 'runtime_load_failed', reason: runtime.reason }))
    return runtime
}

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        return handle(request, await runtimeFor(env), deps)
    },
} satisfies ExportedHandler<Env>
