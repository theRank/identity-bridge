import { handle } from '../app'
import type { Deps, RuntimeFailure } from '../types'

// Until the runtime is loaded from configuration, keys and secrets, every request is answered in failure mode
const runtime: RuntimeFailure = { reason: 'runtime loading not implemented' }

// Wrapped, because Workers methods detached from their object throw Illegal invocation
const deps: Deps = {
    fetch: (input, init) => fetch(input, init),
    now: () => Date.now(),
    randomUUID: () => crypto.randomUUID(),
    log: (line) => console.log(JSON.stringify(line)),
}

export default {
    async fetch(request, _env, _ctx): Promise<Response> {
        return handle(request, runtime, deps)
    },
} satisfies ExportedHandler<Env>
