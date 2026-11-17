// Read bundled dependencies' licences at build time so notices follow dependency upgrades.

import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Metafile } from 'esbuild'

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

export interface Banner {
    text: string
    packages: string[]
}

export function banner(root: string, metafile: Metafile): Banner {
    const directories = [...new Set(Object.keys(metafile.inputs).flatMap((input) => PACKAGE.exec(input)?.[1] ?? []))].sort()
    const licences = directories.map((directory) => {
        const { name, version } = JSON.parse(readFileSync(join(root, directory, 'package.json'), 'utf8')) as { name: string; version: string }
        const file = readdirSync(join(root, directory)).find((entry) => LICENCE.test(entry))
        if (file === undefined) throw new Error(`${name} has no licence file to bundle with it`)
        const text = readFileSync(join(root, directory, file), 'utf8').trim()
        if (text.includes('*/')) throw new Error(`the licence of ${name} would end the comment holding it`)
        return `/*! ${name} ${version}, from ${file}:\n\n${text}\n*/`
    })
    return {
        text: [NOTICE, ...licences].join('\n\n'),
        packages: directories.map((directory) => directory.slice(directory.lastIndexOf('node_modules/') + 13)),
    }
}
