import { Agent, request, type IncomingHttpHeaders, type Server } from 'node:http'
import { connect, type AddressInfo } from 'node:net'

export interface Answer {
    status: number
    headers: IncomingHttpHeaders
    body: string
}

export interface Ask {
    method?: string
    // Sent as the request target exactly as given, so it can be absolute-form
    path: string
    // An array value is sent as repeated header lines
    headers?: Record<string, string | number | string[]>
    // Written one part at a time
    body?: (string | Uint8Array)[]
    // false leaves the body unfinished, as a client still sending it would
    end?: boolean
}

export async function listen(server: Server): Promise<string> {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`
}

// Through node:http rather than fetch, which normalizes the target, sets Host itself and joins repeated headers.
// The agent keeps connections alive, so a Connection: close in the answer is the server's own choice.
export function ask(origin: string, options: Ask): Promise<Answer> {
    const { hostname, port } = new URL(origin)
    const agent = new Agent({ keepAlive: true })
    return new Promise<Answer>((resolve, reject) => {
        const req = request({ host: hostname, port, method: options.method ?? 'GET', path: options.path, headers: options.headers, agent })
        req.on('error', reject)
        req.on('response', (res) => {
            let body = ''
            res.setEncoding('utf8')
            res.on('data', (chunk: string) => (body += chunk))
            res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body }))
            res.on('error', reject)
        })
        for (const part of options.body ?? []) req.write(part)
        if (options.end !== false) req.end()
    }).finally(() => agent.destroy())
}

// Writes the bytes as given over a plain socket and reads everything the server sends until it closes, for
// requests that node:http's client handles specially, such as CONNECT
export function exchange(origin: string, text: string): Promise<string> {
    const { hostname, port } = new URL(origin)
    return new Promise((resolve, reject) => {
        const socket = connect(Number(port), hostname)
        let received = ''
        socket.setEncoding('utf8')
        socket.on('data', (chunk: string) => (received += chunk))
        socket.on('error', reject)
        socket.on('close', () => resolve(received))
        socket.write(text)
    })
}
