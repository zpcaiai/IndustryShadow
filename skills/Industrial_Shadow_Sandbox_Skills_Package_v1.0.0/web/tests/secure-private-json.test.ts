import {
  chmodSync,
  linkSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import { readPrivateJsonObject } from '../e2e/secure-private-json'

const directories: string[] = []

function privateJson(): string {
  const directory = mkdtempSync(join(tmpdir(), 'shadow-oidc-secrets-'))
  directories.push(directory)
  const path = join(directory, 'secrets.json')
  writeFileSync(path, '{"schema_version":1}\n', { encoding: 'utf8', mode: 0o600 })
  chmodSync(path, 0o600)
  return path
}

afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true })
})

describe('production OIDC private JSON reader', () => {
  it('reads an owner-only regular file through its descriptor', () => {
    expect(readPrivateJsonObject(privateJson())).toEqual({ schema_version: 1 })
  })

  it('rejects group-readable files, symbolic links, and hard links', () => {
    const publicPath = privateJson()
    chmodSync(publicPath, 0o640)
    expect(() => readPrivateJsonObject(publicPath)).toThrow(/owner-only/)

    const linkTarget = privateJson()
    const symbolicLink = `${linkTarget}.symlink`
    symlinkSync(linkTarget, symbolicLink)
    expect(() => readPrivateJsonObject(symbolicLink)).toThrow()

    const hardLinkTarget = privateJson()
    const hardLink = `${hardLinkTarget}.hardlink`
    linkSync(hardLinkTarget, hardLink)
    expect(() => readPrivateJsonObject(hardLinkTarget)).toThrow(/owner-only/)
  })

  it('rejects a file outside the configured byte bound', () => {
    const path = privateJson()
    writeFileSync(path, JSON.stringify({ value: 'x'.repeat(128) }), {
      encoding: 'utf8',
      mode: 0o600,
    })
    chmodSync(path, 0o600)
    expect(() => readPrivateJsonObject(path, 32)).toThrow(/bounded/)
  })
})
