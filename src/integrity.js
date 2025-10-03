const { createHash } = require('crypto')

/**
 * Extracts the signable content from a policy object.
 *
 * @param {Object} [policy] - MFKDF policy object
 * @returns {Buffer} The extracted data
 * @since 2.0.0
 * @async
 */
export async function extract(policy) {
  const hash = createHash('sha256')

  hash.update(await extractPolicyCore(policy))

  for (const factor of policy.factors) {
    hash.update(await extractFactor(factor))
  }

  return hash.digest()
}

// Extracts the core signable content from a policy object.
async function extractPolicyCore(policy) {
  const hash = createHash('sha256')

  hash.update(policy.$id)
  hash.update(policy.threshold.toString())
  hash.update(policy.salt)

  return hash.digest()
}

// Extracts the signable content from a factor object.
async function extractFactor(factor) {
  const hash = createHash('sha256')

  hash.update(await extractFactorCore(factor))
  hash.update(await extractFactorParams(factor))

  return hash.digest()
}

// Extracts the core signable content from a factor object.
async function extractFactorCore(factor) {
  const hash = createHash('sha256')

  hash.update(factor.id)
  hash.update(factor.type)
  hash.update(factor.pad)
  hash.update(factor.salt)
  hash.update(factor.secret)

  return hash.digest()
}

// Extracts the signable content from a factor's params object.
async function extractFactorParams(factor) {
  const hash = createHash('sha256')

  hash.update(JSON.stringify(factor.params))

  return hash.digest()
}
