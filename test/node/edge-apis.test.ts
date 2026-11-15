import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { transformSync } from 'esbuild'
import { describe, expect, it } from 'vitest'

const ROOT = fileURLToPath(new URL('../..', import.meta.url).href)
const SRC = join(ROOT, 'src')

// APIs that ESA lacks, though the Workers runtime the tests run in has them; with no local ESA runtime, only this
// check stops the source from using them
const MISSING_ON_ESA: [name: string, uses: RegExp[]][] = [
    [
        'URL.parse',
        [
            /\bURL\s*(?:\?\.|\.)\s*parse\b/,
            /\bURL\s*(?:\?\.)?\[\s*['"`]parse['"`]\s*\]/,
            // Destructured, as in const { parse } = URL
            /\{[^}]*\bparse\b[^}]*\}\s*=\s*(?:globalThis\s*\.\s*)?URL\b/,
        ],
    ],
    ['performance', [/\bperformance\b/]],
]

// The code without its comments, which may name the APIs to explain why they are avoided
function uses(source: string): string[] {
    const { code } = transformSync(source, { loader: 'ts', legalComments: 'none' })
    return MISSING_ON_ESA.filter(([, uses]) => uses.some((use) => use.test(code))).map(([name]) => name)
}

function sources(directory: string): string[] {
    return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
        const path = join(directory, entry.name)
        if (entry.isDirectory()) return sources(path)
        return entry.name.endsWith('.ts') ? [path] : []
    })
}

describe('APIs missing on ESA', () => {
    it.each([
        ['const url = URL.parse(input)', ['URL.parse']],
        ['const parse = URL.parse', ['URL.parse']],
        ['const url = URL?.parse(input)', ['URL.parse']],
        ["const url = URL['parse'](input)", ['URL.parse']],
        ['const { parse } = URL', ['URL.parse']],
        ['const { canParse, parse: parseUrl } = globalThis.URL', ['URL.parse']],
        ['const { parse } = JSON', []],
        ['const start = performance.now()', ['performance']],
        ['const start = globalThis.performance.now()', ['performance']],
        ['// URL.parse is missing on ESA\nconst url = new URL(input)', []],
        ['/* performance.now() */ const start = Date.now()', []],
        ['/**\n * Not URL.parse: not every edge runtime has it\n */\nexport function parse(input: string): URL {\n    return new URL(input)\n}', []],
    ])('finds the uses in %j', (source, expected) => {
        expect(uses(source)).toEqual(expected)
    })

    it('are not used by any source under src/', () => {
        const files = sources(SRC)
        const found = files.flatMap((file) => uses(readFileSync(file, 'utf8')).map((name) => `${relative(ROOT, file)}: ${name}`))

        expect(files.length).toBeGreaterThan(10)
        expect(found).toEqual([])
    })
})
