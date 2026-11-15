// Bundles the ESA entry into dist/esa/esa.js, the single file an ESA Functions and Pages routine runs: ESM for a
// Workers-like platform, with jose built in and opening with the licence banner of scripts/licence.ts. Fails if the
// bundle would import anything, which ESA cannot resolve, or exceed ESA's code package limit.
//
//     node scripts/build-esa.ts

import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import { banner } from './licence.ts'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const OUTFILE = join(ROOT, 'dist/esa/esa.js')
// ESA's limit of 4 MB, read as decimal megabytes, the smaller of the two readings
const LIMIT = 4_000_000

const result = await build({
    absWorkingDir: ROOT,
    entryPoints: ['src/runtimes/esa.ts'],
    bundle: true,
    platform: 'browser',
    conditions: ['workerd', 'worker', 'browser'],
    format: 'esm',
    // What ESA ran in the probe
    target: 'es2022',
    outfile: OUTFILE,
    metafile: true,
    write: false,
})

const [output] = result.outputFiles
if (output === undefined) throw new Error('esbuild wrote no bundle')
const imports = Object.values(result.metafile.outputs).flatMap((file) => file.imports.map((entry) => entry.path))
if (imports.length > 0) throw new Error(`the bundle imports ${imports.join(', ')}, and ESA runs a single file`)
const { text, packages } = banner(ROOT, result.metafile)
const bundle = `${text}\n\n${output.text}`
const bytes = Buffer.byteLength(bundle)
if (bytes > LIMIT) throw new Error(`the bundle is ${bytes} bytes, over ESA's limit of ${LIMIT}`)
mkdirSync(dirname(OUTFILE), { recursive: true })
writeFileSync(OUTFILE, bundle)
process.stdout.write(`${OUTFILE.slice(ROOT.length)}: ${output.contents.byteLength} bytes of code, licences of ${packages.join(', ')}\n`)
