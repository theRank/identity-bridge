// Bundles the Node entry into dist/node/server.mjs, with jose built in, so that it runs alone with plain node.
// The bundle opens with a banner holding the bridge's licence notice and the full licence of every package
// bundled into it, read from node_modules at build time, so the notices follow upgrades.
//
//     node scripts/build-node.ts

import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const OUTFILE = join(ROOT, 'dist/node/server.mjs')
// A package's directory in an input path, such as node_modules/jose for node_modules/jose/dist/webapi/index.js
const PACKAGE = /^(.*?node_modules\/(?:@[^/]+\/)?[^/]+)\//
const LICENCE = /^licen[cs]e(\.(md|txt))?$/i

const NOTICE = [
    '/*!',
    ' * identity-bridge',
    ' * https://github.com/theRank/identity-bridge',
    ' * Licensed under the Apache License, Version 2.0: https://www.apache.org/licenses/LICENSE-2.0',
    ' *',
    ' * This file also contains the packages below, each under its own licence.',
    ' */',
].join('\n')

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

const packages = [...new Set(Object.keys(result.metafile.inputs).flatMap((input) => PACKAGE.exec(input)?.[1] ?? []))].sort()
const licences = packages.map((directory) => {
    const { name, version } = JSON.parse(readFileSync(join(ROOT, directory, 'package.json'), 'utf8')) as { name: string; version: string }
    const file = readdirSync(join(ROOT, directory)).find((entry) => LICENCE.test(entry))
    if (file === undefined) throw new Error(`${name} has no licence file to bundle with it`)
    const text = readFileSync(join(ROOT, directory, file), 'utf8').trim()
    if (text.includes('*/')) throw new Error(`the licence of ${name} would end the comment holding it`)
    return `/*! ${name} ${version}, from ${file}:\n\n${text}\n*/`
})

const [output] = result.outputFiles
if (output === undefined) throw new Error('esbuild wrote no bundle')
mkdirSync(dirname(OUTFILE), { recursive: true })
writeFileSync(OUTFILE, `${[NOTICE, ...licences].join('\n\n')}\n\n${output.text}`)
process.stdout.write(`${OUTFILE.slice(ROOT.length)}: ${output.contents.byteLength} bytes of code, licences of ${packages.map((directory) => directory.slice(directory.lastIndexOf('node_modules/') + 13)).join(', ')}\n`)
