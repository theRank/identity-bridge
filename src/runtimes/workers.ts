import { type Env, serve } from './edge'

export type { Env } from './edge'

export default {
    fetch(request: Request, env: Env): Promise<Response> {
        return serve(request, env)
    },
} satisfies ExportedHandler<Env>
