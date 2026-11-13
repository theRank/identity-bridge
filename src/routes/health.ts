import { json } from '../http'
import { cryptoSelfTest } from '../selftest'
import type { RouteHandler } from '../types'

// No cache between the bridge and a monitor may hide a failure or a recovery
const NO_STORE = { 'cache-control': 'no-store' }

export const healthRoute: RouteHandler = async () =>
    (await cryptoSelfTest()) ? json(200, { status: 'ok' }, NO_STORE) : json(503, { status: 'unavailable' }, NO_STORE)
