import { empty } from '../http'
import type { RouteHandler } from '../types'

export const healthRoute: RouteHandler = async () => empty(501)
