import { json } from '../http'
import { cryptoSelfTest } from '../selftest'
import type { RouteHandler } from '../types'

export const healthRoute: RouteHandler = async () => ((await cryptoSelfTest()) ? json(200, { status: 'ok' }) : json(503, { status: 'unavailable' }))
