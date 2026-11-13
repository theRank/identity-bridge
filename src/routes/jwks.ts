import { json } from '../http'
import type { PublicJwk, RouteHandler } from '../types'

export const jwksRoute: RouteHandler = async (_request, runtime) =>
    json(200, { keys: runtime.keys.jwks.keys.map(publicMembers) }, { 'cache-control': 'public, max-age=300' })

// Members are copied one by one, so nothing else a key object holds can ever be published
function publicMembers({ kty, crv, x, y, kid, alg, use }: PublicJwk): PublicJwk {
    return { kty, crv, x, y, kid, alg, use }
}
