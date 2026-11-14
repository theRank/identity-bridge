// Checks a release tag for the release workflows, and says what to publish under it:
//
//     node scripts/release-tag.ts <tag> [<file of the existing tags, one per line>]
//
// Prints version=, prerelease= and, given the existing tags, latest= and dist_tag= lines, as $GITHUB_OUTPUT takes
// them. A tag is v and a semver version without build metadata, which a Docker tag cannot hold; anything else exits
// 1. latest is true only for the highest version that is not a prerelease, by semver precedence, and dist_tag is
// the npm dist-tag that follows the same rule.

import { readFileSync } from 'node:fs'

// semver.org's pattern, after a v and without its build metadata part
const TAG =
    /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?$/
const NUMERIC = /^\d+$/

export interface Version {
    // Without the v
    text: string
    core: [major: bigint, minor: bigint, patch: bigint]
    prerelease: string[]
}

export function parseTag(tag: string): Version | undefined {
    const match = TAG.exec(tag)
    if (match === null) return undefined
    const [, major, minor, patch, prerelease] = match
    return { text: tag.slice(1), core: [BigInt(major!), BigInt(minor!), BigInt(patch!)], prerelease: prerelease?.split('.') ?? [] }
}

// Semver precedence: numbers as numbers, however long; a prerelease before its release; prerelease identifiers in
// turn, a numeric one before an alphanumeric one, and a longer list after a shorter one it begins with
export function compare(a: Version, b: Version): number {
    for (let index = 0; index < 3; index++) {
        const order = sign(a.core[index]! - b.core[index]!)
        if (order !== 0) return order
    }
    if (a.prerelease.length === 0 || b.prerelease.length === 0) return sign(BigInt(b.prerelease.length - a.prerelease.length))
    for (let index = 0; index < Math.min(a.prerelease.length, b.prerelease.length); index++) {
        const order = compareIdentifiers(a.prerelease[index]!, b.prerelease[index]!)
        if (order !== 0) return order
    }
    return sign(BigInt(a.prerelease.length - b.prerelease.length))
}

// Tags that are not versions are ignored
export function isLatest(version: Version, tags: string[]): boolean {
    if (version.prerelease.length > 0) return false
    return tags.every((tag) => {
        const other = parseTag(tag)
        return other === undefined || other.prerelease.length > 0 || compare(other, version) <= 0
    })
}

// latest for the highest release, as for the image; release-X.Y for a patch to an older line, the prefix because
// npm refuses a dist-tag that is a valid semver range, such as 1.4; next for a prerelease
export function distTag(version: Version, tags: string[]): string {
    if (version.prerelease.length > 0) return 'next'
    if (isLatest(version, tags)) return 'latest'
    const [major, minor] = version.core
    return `release-${major}.${minor}`
}

function compareIdentifiers(a: string, b: string): number {
    const numeric = [NUMERIC.test(a), NUMERIC.test(b)]
    if (numeric[0] && numeric[1]) return sign(BigInt(a) - BigInt(b))
    if (numeric[0] !== numeric[1]) return numeric[0] ? -1 : 1
    return a < b ? -1 : a > b ? 1 : 0
}

function sign(value: bigint): number {
    return value < 0n ? -1 : value > 0n ? 1 : 0
}

if (import.meta.main) {
    const [tag, tagsFile] = process.argv.slice(2)
    const version = tag === undefined ? undefined : parseTag(tag)
    if (version === undefined) {
        process.stderr.write(`::error::${tag ?? 'no tag'} is not v followed by a semver version without build metadata, such as v1.2.3 or v1.2.3-rc.1\n`)
        process.exit(1)
    }
    const lines = [`version=${version.text}`, `prerelease=${version.prerelease.length > 0}`]
    if (tagsFile !== undefined) {
        const tags = readFileSync(tagsFile, 'utf8').split('\n').map((line) => line.trim())
        lines.push(`latest=${isLatest(version, tags)}`, `dist_tag=${distTag(version, tags)}`)
    }
    process.stdout.write(`${lines.join('\n')}\n`)
}
