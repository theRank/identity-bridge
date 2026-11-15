import { type Env, serve } from './edge'

// Read for an env that is not an object: the runtime fails to load and answers in failure mode, logging why once,
// rather than the handler throwing on every request
const EMPTY: Env = Object.freeze({})

// ESA Functions and Pages passes the variables third, after a context of which the bridge needs nothing
export default {
    fetch(request: Request, _context: unknown, env: unknown): Promise<Response> {
        return serve(request, typeof env === 'object' && env !== null ? (env as Env) : EMPTY)
    },
}
