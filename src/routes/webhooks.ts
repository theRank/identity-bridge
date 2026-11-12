import { empty } from '../http'
import type { RouteHandler } from '../types'

export const webhooksRoute: RouteHandler = async () => empty(501)
