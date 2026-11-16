import { handle } from '../app'
import type { Deps, Runtime, RuntimeFailure } from '../types'
import { loadRuntime, webhookSecretName } from './load'

// Shared by the Workers and ESA entries, which pass the deployment's env object in different arguments

// Declared here rather than generated: each deployment names its own webhook sources, so their secrets cannot be
// declared in this repository
export interface Env {
    // A string, or the JSON value wrangler gives for a configuration written as an object under vars
    BRIDGE_CONFIG?: string | object | undefined
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

// Keyed by env, one object for the life of an isolate, so the parsed configuration and the IdP key sets cached by
// it last as long as the isolate rather than a request
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
        config: typeof env.BRIDGE_CONFIG === 'object' ? JSON.stringify(env.BRIDGE_CONFIG) : env.BRIDGE_CONFIG,
        signingKeys: env.SIGNING_KEYS,
        webhookSecret: (sourceId) => env[webhookSecretName(sourceId)],
    })
    if ('reason' in runtime) console.log(JSON.stringify({ event: 'runtime_load_failed', reason: runtime.reason }))
    return runtime
}

export async function serve(request: Request, env: Env): Promise<Response> {
    return handle(request, await runtimeFor(env), deps)
}
