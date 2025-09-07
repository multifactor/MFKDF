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
const kdf = require('../kdf').kdf
const { hkdfSync } = require('crypto')
const xor = require('buffer-xor')
const MFKDFDerivedKey = require('../classes/MFKDFDerivedKey')

/**
 * Derive a key from multiple factors of input
 *
 * @example
 * // setup 16 byte 2-of-3-factor multi-factor derived key with a password, HOTP code, and UUID recovery code
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.password('password'),
 *   await mfkdf.setup.factors.hotp({ secret: Buffer.from('hello world') }),
 *   await mfkdf.setup.factors.uuid({ id: 'recovery', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
 * ], {threshold: 2, size: 16})
 *
 * // derive key using 2 of the 3 factors
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   password: mfkdf.derive.factors.password('password'),
 *   hotp: mfkdf.derive.factors.hotp(365287)
 * })
 *
 * setup.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
 * derive.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
 *
 * @param {Object} policy - The key policy for the key being derived
 * @param {Object.<string, MFKDFFactor>} factors - Factors used to derive this key
 * @returns {MFKDFDerivedKey} A multi-factor derived key object
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.9.0
 * @async
 * @memberOf derive
 */
async function key (policy, factors) {
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
        let stretched = Buffer.from(
          hkdfSync('sha512', material.data, '', '', policy.size)
        )
        if (Buffer.byteLength(pad) > policy.size) {
          stretched = Buffer.concat([
            Buffer.alloc(Buffer.byteLength(pad) - policy.size),
            stretched
          ])
        }

        share = xor(pad, stretched)
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
  const key = await kdf(
    secret,
    Buffer.from(policy.salt, 'base64'),
    policy.size,
    policy.kdf
  )

  const newPolicy = JSON.parse(JSON.stringify(policy))

  for (const [index, factor] of newFactors.entries()) {
    if (typeof factor === 'function') {
      newPolicy.factors[index].params = await factor({ key })
    }
  }

  const originalShares = recover(
    shares,
    policy.threshold,
    policy.factors.length
  )

  return new MFKDFDerivedKey(newPolicy, key, secret, originalShares, outputs)
}
module.exports.key = key
