import type { AddressInfo } from 'node:net'
import { constants } from 'node:os'
import { setTimeout as sleep } from 'node:timers/promises'
import { createNodeServer, listenAddress, shutdown } from './node'

// Below Docker's default stop grace period of 10 s, so the deadline, not a kill, ends a stop
const GRACE_MS = 8_000

const log = (text: string) => void process.stdout.write(`${text}\n`)
const { server } = createNodeServer({ env: process.env, log })
const { port, host } = listenAddress(process.env)

server.listen(port, host, () => {
    const address = server.address() as AddressInfo
    log(JSON.stringify({ event: 'listening', host: address.address, port: address.port }))
})

let stopping = false

// As PID 1 in a container a signal without a handler is ignored, so the handler stays: a second signal exits at
// once, with 128 + its number, the code of a process that signal killed
function stop(signal: NodeJS.Signals): void {
    if (stopping) process.exit(128 + constants.signals[signal])
    stopping = true
    const stopped = shutdown(server, sleep(GRACE_MS, undefined, { ref: false }))
    // Only once the listener has closed, so the line means new connections are refused
    log(JSON.stringify({ event: 'stopping', signal }))
    // 1 when the deadline cut requests off. Exits once stdout has taken every line, which on a pipe is written
    // asynchronously.
    void stopped.then((clean) => process.stdout.write('', () => process.exit(clean ? 0 : 1)))
}

process.on('SIGTERM', stop)
process.on('SIGINT', stop)
