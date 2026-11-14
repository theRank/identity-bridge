import type { AddressInfo } from 'node:net'
import { setTimeout as sleep } from 'node:timers/promises'
import { createNodeServer, shutdown } from './node'

const GRACE_MS = 10_000

const log = (text: string) => void process.stdout.write(`${text}\n`)
const { server } = createNodeServer({ env: process.env, log })

// An empty value counts as unset, so PORT= does not mean a random port
server.listen(Number(process.env.PORT || 8080), process.env.HOST || '0.0.0.0', () => {
    const { address, port } = server.address() as AddressInfo
    log(JSON.stringify({ event: 'listening', host: address, port }))
})

// As PID 1 in a container Node has no default signal handlers, so without these a stop would wait out its grace
// period and be killed. A second signal gets the default handling again and stops the process at once.
function stop(signal: NodeJS.Signals): void {
    process.off('SIGTERM', stop)
    process.off('SIGINT', stop)
    const stopped = shutdown(server, sleep(GRACE_MS, undefined, { ref: false }))
    log(JSON.stringify({ event: 'stopping', signal }))
    // Exits once stdout has taken every line, which on a pipe is written asynchronously
    void stopped.then(() => process.stdout.write('', () => process.exit(0)))
}

process.on('SIGTERM', stop)
process.on('SIGINT', stop)
