const { createHash } = require('crypto')

// Deterministically stringify by sorting object keys at all depths
function stableStringify(value) {
  function normalize(val) {
    if (Array.isArray(val)) return val.map(normalize)
    if (val && typeof val === 'object') {
      const out = {}
      for (const k of Object.keys(val).sort()) {
        if (val[k] === undefined) continue
        out[k] = k === 'params' && typeof val.params !== 'string'
          ? JSON.stringify(normalize(val.params))
          : normalize(val[k])
      }
      return out
    }
    return val
  }
  return JSON.stringify(normalize(value))
}

/**
 * Extracts the signable content from a policy object.
 *
 * @param {Object} [policy] - MFKDF policy object
 * @returns {Buffer} The extracted data
 * @since 2.0.0
 * @async
 */
async function extract (policy) {
  const hash = createHash('sha256')

  hash.update(await extractPolicyCore(policy))

  for (const factor of policy.factors) {
    hash.update(await extractFactor(factor))
  }

  return hash.digest()
}

// Extracts the core signable content from a policy object.
async function extractPolicyCore (policy) {
  const hash = createHash('sha256')

  hash.update(policy.$id)
  hash.update(policy.threshold.toString())
  hash.update(policy.salt)

  return hash.digest()
}

// Extracts the signable content from a factor object.
async function extractFactor (factor) {
  const hash = createHash('sha256')

  hash.update(await extractFactorCore(factor))
  hash.update(await extractFactorParams(factor))

  return hash.digest()
}

// Extracts the core signable content from a factor object.
async function extractFactorCore (factor) {
  const hash = createHash('sha256')

  hash.update(factor.id)
  hash.update(factor.type)
  hash.update(factor.pad)
  hash.update(factor.salt)
  hash.update(factor.secret)

  return hash.digest()
}

// Extracts the signable content from a factor's params object.
async function extractFactorParams (factor) {
  const hash = createHash('sha256')

  // IMP: sort params to ensure consistent hash
  hash.update(stableStringify(factor.params))

  return hash.digest()
}

module.exports.extract = extract
