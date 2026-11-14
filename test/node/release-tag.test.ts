import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'
import { compare, isLatest, parseTag } from '../../scripts/release-tag'

const SCRIPT = fileURLToPath(new URL('../../scripts/release-tag.ts', import.meta.url).href)
const dir = mkdtempSync(join(tmpdir(), 'identity-bridge-tags-'))

afterAll(() => rmSync(dir, { recursive: true, force: true }))

function run(...args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [SCRIPT, ...args])
        let stdout = ''
        let stderr = ''
        child.stdout.on('data', (chunk) => (stdout += String(chunk)))
        child.stderr.on('data', (chunk) => (stderr += String(chunk)))
        child.on('error', reject)
        child.on('close', (code) => resolve({ code, stdout, stderr }))
    })
}

function version(tag: string) {
    const parsed = parseTag(tag)
    if (parsed === undefined) throw new Error(`${tag} does not parse`)
    return parsed
}

describe('parseTag', () => {
    it.each([
        ['v01.2.3', 'a leading zero'],
        ['v1.2.3-.', 'an empty prerelease identifier'],
        ['v1.2.3-rc..1', 'an empty prerelease identifier between dots'],
        ['v1.2.3-rc.01', 'a numeric prerelease identifier with a leading zero'],
        ['v1.2.3+build', 'build metadata, which a Docker tag cannot hold'],
        ['v1.2.3-rc.1+build.5', 'build metadata after a prerelease'],
        ['1.2.3', 'no v'],
        ['v1.2', 'no patch'],
        ['v1.2.3-', 'a dangling hyphen'],
        ['vnext', 'no version'],
        ['v1.2.3 ', 'a trailing space'],
    ])('refuses %s, with %s', (tag) => {
        expect(parseTag(tag)).toBeUndefined()
    })

    it.each([
        ['v1.2.3', '1.2.3', []],
        ['v1.2.3-rc.1', '1.2.3-rc.1', ['rc', '1']],
        ['v1.10.0', '1.10.0', []],
        ['v0.0.0-dry-run', '0.0.0-dry-run', ['dry-run']],
        ['v1.2.3-0.alpha-1', '1.2.3-0.alpha-1', ['0', 'alpha-1']],
    ])('accepts %s as %s', (tag, text, prerelease) => {
        expect(parseTag(tag)).toMatchObject({ text, prerelease })
    })
})

describe('compare', () => {
    // The order semver.org gives, and numbers compared as numbers, however long
    const ORDERED = [
        'v1.0.0-alpha',
        'v1.0.0-alpha.1',
        'v1.0.0-alpha.beta',
        'v1.0.0-beta',
        'v1.0.0-beta.2',
        'v1.0.0-beta.11',
        'v1.0.0-rc.1',
        'v1.0.0',
        'v1.9.0',
        'v1.10.0',
        'v1.11.0-rc.1',
        'v1.11.0',
        'v2.0.0',
        'v18446744073709551616.0.0',
        'v18446744073709551617.0.0',
    ]

    it('orders versions by semver precedence', () => {
        const shuffled = [...ORDERED].reverse()
        shuffled.push(shuffled.shift()!)

        expect(shuffled.sort((a, b) => compare(version(a), version(b)))).toEqual(ORDERED)
    })

    it('finds equal versions equal', () => {
        expect(compare(version('v1.2.3-rc.1'), version('v1.2.3-rc.1'))).toBe(0)
    })
})

describe('isLatest', () => {
    it.each<[string, string[], boolean]>([
        ['v1.3.0', ['v1.2.0', 'v1.3.0', 'v1.2.4'], true],
        ['v1.2.4', ['v1.2.0', 'v1.3.0', 'v1.2.4'], false],
        ['v1.10.0', ['v1.9.0', 'v1.10.0'], true],
        ['v2.0.0', ['v1.0.0', 'v2.0.0', 'v2.1.0-rc.1'], true],
        ['v2.1.0-rc.1', ['v1.0.0', 'v2.0.0', 'v2.1.0-rc.1'], false],
        ['v1.0.0', ['v1.0.0'], true],
        ['v1.0.0', ['v1.0.0', 'vnext', 'v9.0', 'v9.0.0+build', 'v01.0.0'], true],
    ])('%s among %j is %s', (tag, tags, latest) => {
        expect(isLatest(version(tag), tags)).toBe(latest)
    })
})

describe('the script', () => {
    it('prints the version and whether it is a prerelease', async () => {
        expect(await run('v1.2.3-rc.1')).toEqual({ code: 0, stdout: 'version=1.2.3-rc.1\nprerelease=true\n', stderr: '' })
    })

    it('says whether the version is the latest, given the existing tags one per line', async () => {
        const tags = join(dir, 'tags')
        writeFileSync(tags, 'v1.2.0\nv1.3.0\nv1.2.4\n')

        expect((await run('v1.3.0', tags)).stdout).toBe('version=1.3.0\nprerelease=false\nlatest=true\n')
        expect((await run('v1.2.4', tags)).stdout).toBe('version=1.2.4\nprerelease=false\nlatest=false\n')
    })

    it('exits 1 on a tag that is not a version, saying why', async () => {
        const { code, stdout, stderr } = await run('v1.2.3+build')

        expect(code).toBe(1)
        expect(stdout).toBe('')
        expect(stderr).toMatch(/^::error::v1\.2\.3\+build is not v followed by a semver version without build metadata/)
    })

    it('exits 1 without a tag', async () => {
        expect((await run()).code).toBe(1)
    })
})
