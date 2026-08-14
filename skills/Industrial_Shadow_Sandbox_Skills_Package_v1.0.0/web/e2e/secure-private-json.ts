import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readSync,
  type BigIntStats,
} from 'node:fs'
import { resolve } from 'node:path'

const DEFAULT_MAXIMUM_BYTES = 1024 * 1024
const MAXIMUM_CONFIGURABLE_BYTES = 16 * 1024 * 1024

function isStableFile(before: BigIntStats, after: BigIntStats): boolean {
  return (
    before.dev === after.dev &&
    before.ino === after.ino &&
    before.mode === after.mode &&
    before.nlink === after.nlink &&
    before.uid === after.uid &&
    before.gid === after.gid &&
    before.size === after.size &&
    before.mtimeNs === after.mtimeNs &&
    before.ctimeNs === after.ctimeNs
  )
}

function validatePrivateFile(stat: BigIntStats, maximumBytes: number): void {
  if (typeof process.geteuid !== 'function')
    throw new Error('OIDC browser secrets require a POSIX owner check')
  const permissions = stat.mode & 0o777n
  if (
    !stat.isFile() ||
    stat.nlink !== 1n ||
    stat.uid !== BigInt(process.geteuid()) ||
    ![0o400n, 0o600n].includes(permissions) ||
    stat.size < 1n ||
    stat.size > BigInt(maximumBytes)
  ) throw new Error('OIDC browser secrets must be a bounded owner-only regular file')
}

/** Read one private JSON object through one O_NOFOLLOW descriptor. */
export function readPrivateJsonObject<T>(
  pathValue: string,
  maximumBytes = DEFAULT_MAXIMUM_BYTES,
): T {
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > MAXIMUM_CONFIGURABLE_BYTES
  )
    throw new Error('OIDC browser secrets size limit is invalid')
  const path = resolve(pathValue)
  let descriptor: number | undefined
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    const before = fstatSync(descriptor, { bigint: true })
    validatePrivateFile(before, maximumBytes)

    const buffer = Buffer.allocUnsafe(maximumBytes + 1)
    let offset = 0
    while (offset < buffer.length) {
      const count = readSync(descriptor, buffer, offset, buffer.length - offset, null)
      if (count === 0) break
      offset += count
    }
    const after = fstatSync(descriptor, { bigint: true })
    validatePrivateFile(after, maximumBytes)
    if (!isStableFile(before, after) || offset !== Number(before.size))
      throw new Error('OIDC browser secrets changed while being read')

    const value: unknown = JSON.parse(buffer.subarray(0, offset).toString('utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new Error('OIDC browser secrets must contain one JSON object')
    return value as T
  } finally {
    if (descriptor !== undefined) closeSync(descriptor)
  }
}
