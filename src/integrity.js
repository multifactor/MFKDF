const { createHash } = require('crypto')

// Deterministically stringify by sorting object keys at all depths
function stableStringify(value) {
  return JSON.stringify(value, function replacer(key, val) {
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      const sortedKeys = Object.keys(val).sort()
      const sortedObj = {}
      for (const k of sortedKeys) {
        sortedObj[k] = val[k]
      }
      return sortedObj
    }
    return val
  })
}
// Mirror Rust serde_json struct field order for Policy and PolicyFactor
function rustPolicyStringify(policy) {
  const orderPolicy = [
    '$id',
    '$schema',
    'factors',
    'key',
    'memory',
    'salt',
    'threshold',
    'time'
  ]
  const orderFactor = ['id', 'pad', 'params', 'salt', 'secret', 'type']

  function orderValue(value, order) {
    if (Array.isArray(value)) {
      return value.map((item) => orderValue(item, orderFactor))
    }

    if (value && typeof value === 'object') {
      const ordered = {}
      const baseKeys = order ? order : []
      const extras = Object.keys(value).filter((k) => !baseKeys.includes(k)).sort()
      const keys = [...baseKeys, ...extras]
      for (const key of keys) {
        if (value[key] === undefined) continue
        if (key === 'params') {
          ordered.params = typeof value.params === 'string'
            ? value.params
            : JSON.stringify(orderValue(value.params, orderPolicy))
        } else {
          const nextOrder = key === 'factors' ? orderFactor : undefined
          ordered[key] = orderValue(value[key], nextOrder)
        }
      }
      return ordered
    }

    return value
  }

  return JSON.stringify(orderValue(policy, orderPolicy))
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
  let params
  if (factor.type === 'stack') {
    params = rustPolicyStringify(factor.params)
  } else {
    params = stableStringify(factor.params)
  }  
  hash.update(params)

  return hash.digest()
}

module.exports.extract = extract
