/**
 * @file Multi-factor Key Derivation
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Derive a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const Ajv = require('ajv')
const policySchema = require('./policy.json')
const combine = require('../secrets/combine').combine
const recover = require('../secrets/recover').recover
const { argon2id } = require('hash-wasm')
const MFKDFDerivedKey = require('../classes/MFKDFDerivedKey')
const { decrypt, hkdf } = require('../crypt')
const { extract } = require('../integrity')
const crypto = require('crypto')

/**
 * Derive a key from multiple factors of input
 *
 * @example
 * // setup 16 byte 2-of-3-factor multi-factor derived key with a password, HOTP code, and UUID recovery code
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.password('password'),
 *   await mfkdf.setup.factors.hotp({ secret: Buffer.from('abcdefghijklmnopqrst') }),
 *   await mfkdf.setup.factors.uuid({ id: 'recovery', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
 * ], {threshold: 2})
 *
 * // derive key using 2 of the 3 factors
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   password: mfkdf.derive.factors.password('password'),
 *   hotp: mfkdf.derive.factors.hotp(241063)
 * })
 *
 * setup.key.toString('hex') // -> 34d2…5771
 * derive.key.toString('hex') // -> 34d2…5771
 *
 * @param {Object} policy - The key policy for the key being derived
 * @param {Object.<string, MFKDFFactor>} factors - Factors used to derive this key
 * @param {boolean} [verify=true] - Whether to verify the integrity of the policy after deriving (recommended)
 * @returns {MFKDFDerivedKey} A multi-factor derived key object
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.9.0
 * @async
 * @memberOf derive
 */
async function key (policy, factors, verify = true, stack = false) {
  const ajv = new Ajv()
  const valid = ajv.validate(policySchema, policy)
  if (!valid) throw new TypeError('invalid key policy', ajv.errors)
  if (Object.keys(factors).length < policy.threshold) {
    throw new RangeError('insufficient factors provided to derive key')
  }

  const shares = []
  const newFactors = []
  const outputs = {}

  for (const factor of policy.factors) {
    if (factors[factor.id] && typeof factors[factor.id] === 'function') {
      const material = await factors[factor.id](factor.params)
      let share

      if (material.type === 'persisted') {
        share = material.data
      } else {
        if (material.type !== factor.type) {
          throw new TypeError(
            'wrong factor material function used for this factor type'
          )
        }

        const pad = Buffer.from(factor.pad, 'base64')
        const stretched = Buffer.from(
          await hkdf(
            'sha256',
            material.data,
            Buffer.from(factor.salt, 'base64'),
            'mfkdf2:factor:pad:' + factor.id,
            32
          )
        )

        share = decrypt(pad, stretched)

        if (factor.hint) {
          const buffer = Buffer.from(
            await hkdf(
              'sha256',
              stretched,
              Buffer.from(factor.salt, 'base64'),
              'mfkdf2:factor:hint:' + factor.id,
              32
            )
          )

          const binaryString = [...buffer]
            .map((byte) => byte.toString(2).padStart(8, '0'))
            .reduce((acc, bits) => acc + bits, '')

          const hint = binaryString.slice(-1 * factor.hint.length)

          if (hint !== factor.hint) {
            throw new RangeError('hint does not match for factor ' + factor.id)
          }
        }
      }

      shares.push(share)
      if (material.output) outputs[factor.id] = await material.output()
      newFactors.push(material.params)
    } else {
      shares.push(null)
      newFactors.push(null)
    }
  }

  if (shares.filter((x) => Buffer.isBuffer(x)).length < policy.threshold) {
    throw new RangeError('insufficient factors provided to derive key')
  }

  const secret = combine(shares, policy.threshold, policy.factors.length)

  let kek
  if (stack) {
    kek = Buffer.from(
      await hkdf(
        'sha256',
        secret,
        Buffer.from(policy.salt, 'base64'),
        'mfkdf2:stack:' + policy.$id,
        32
      )
    )
  } else {
    kek = Buffer.from(
      await argon2id({
        password: secret,
        salt: Buffer.from(policy.salt, 'base64'),
        hashLength: 32,
        parallelism: 1,
        iterations: 2 + Math.max(0, parseInt(policy.time) || 0),
        memorySize: 19456 + Math.max(0, parseInt(policy.memory) || 0),
        outputType: 'binary'
      })
    )
  }
  const key = decrypt(Buffer.from(policy.key, 'base64'), kek)

  const newPolicy = JSON.parse(JSON.stringify(policy))

  for (const [index, factor] of newFactors.entries()) {
    if (typeof factor === 'function') {
      const paramsKey = Buffer.from(
        await hkdf(
          'sha256',
          key,
          Buffer.from(newPolicy.factors[index].salt, 'base64'),
          'mfkdf2:factor:params:' + newPolicy.factors[index].id,
          32
        )
      )
      newPolicy.factors[index].params = await factor({ key: paramsKey })
    }
  }

  const integrityKey = await hkdf(
    'sha256',
    key,
    Buffer.from(policy.salt, 'base64'),
    'mfkdf2:integrity',
    32
  )
  if (verify) {
    const integrityData = await extract(policy)
    const hmac = crypto
      .createHmac('sha256', integrityKey)
      .update(integrityData)
      .digest('base64')
    if (policy.hmac !== hmac) {
      throw new RangeError('key policy integrity check failed')
    }
  }
  if (policy.hmac) {
    const newPolicyData = await extract(newPolicy)
    const newHmac = crypto.createHmac('sha256', integrityKey)
    newHmac.update(newPolicyData)
    newPolicy.hmac = newHmac.digest('base64')
  }

  const originalShares = recover(
    shares,
    policy.threshold,
    policy.factors.length
  )

  return new MFKDFDerivedKey(newPolicy, key, secret, originalShares, outputs)
}
module.exports.key = key
