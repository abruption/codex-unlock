import { createHash } from 'node:crypto'

// Version 2 replaces the unversioned files-only digest. JSON domain names,
// record boundaries and fixed field names keep files/interpreters distinct.
export const INPUT_IDENTITY_SCHEMA = 'codex-unlock-g1-input-identity/2'

export function combinedInputDigest(files, interpreters) {
  const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0
  const canonical = (records, name) => {
    if (!Array.isArray(records)) throw new Error(`input_identity_records_invalid:${name}`)
    return records.map((record) => {
      if (record === null || typeof record !== 'object' || Array.isArray(record) ||
        typeof record[name] !== 'string' || record[name].length === 0 ||
        typeof record.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(record.sha256)) {
        // Error markers are failed collection, never hashes of covered bytes.
        throw new Error(`input_identity_record_invalid:${name}`)
      }
      return { [name]: record[name], sha256: record.sha256 }
    }).sort((a, b) => compare(a[name], b[name]) || compare(a.sha256, b.sha256))
  }
  const serialized = JSON.stringify({
    schema: INPUT_IDENTITY_SCHEMA,
    files: canonical(files, 'path'),
    interpreters: canonical(interpreters, 'basename'),
  })
  return createHash('sha256').update(serialized, 'utf8').digest('hex')
}
