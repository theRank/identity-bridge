import { empty } from '../http'
import type { RouteHandler } from '../types'

export const jwksRoute: RouteHandler = async () => empty(501)
