import { type Env, serve } from './edge'

// Reuse one fallback env so a missing environment logs its load failure only once.
const EMPTY: Env = Object.freeze({})

// ESA passes variables as the third argument.
export default {
    fetch(request: Request, _context: unknown, env: unknown): Promise<Response> {
        return serve(request, typeof env === 'object' && env !== null ? (env as Env) : EMPTY)
    },
}
