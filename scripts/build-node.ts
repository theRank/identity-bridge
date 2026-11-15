// Bundles the Node entry into dist/node/server.mjs, with jose built in, so that it runs alone with plain node.
// The bundle opens with the licence banner of scripts/licence.ts.
//
//     node scripts/build-node.ts

import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import { banner } from './licence.ts'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const OUTFILE = join(ROOT, 'dist/node/server.mjs')

const result = await build({
    absWorkingDir: ROOT,
    entryPoints: ['src/runtimes/node-main.ts'],
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node24',
    outfile: OUTFILE,
    metafile: true,
    write: false,
})

const [output] = result.outputFiles
if (output === undefined) throw new Error('esbuild wrote no bundle')
const { text, packages } = banner(ROOT, result.metafile)
mkdirSync(dirname(OUTFILE), { recursive: true })
writeFileSync(OUTFILE, `${text}\n\n${output.text}`)
process.stdout.write(`${OUTFILE.slice(ROOT.length)}: ${output.contents.byteLength} bytes of code, licences of ${packages.join(', ')}\n`)
