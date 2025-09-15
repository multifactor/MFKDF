/**
 * @file MFKDF Stack Factor Setup
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Setup key stacking factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const defaults = require('../../defaults')
const setupKey = require('../key').key

/**
 * Setup an MFKDF stacked key factor
 *
 * @example
 * // setup key with stack factor
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.stack([
 *     await mfkdf.setup.factors.password('password1', {
 *       id: 'password1'
 *     }),
 *     await mfkdf.setup.factors.password('password2', {
 *       id: 'password2'
 *     })
 *   ]),
 *   await mfkdf.setup.factors.password('password3', { id: 'password3' })
 * ])
 *
 * // derive key with stack factor
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   stack: mfkdf.derive.factors.stack({
 *     password1: mfkdf.derive.factors.password('password1'),
 *     password2: mfkdf.derive.factors.password('password2')
 *   }),
 *   password3: mfkdf.derive.factors.password('password3')
 * })
 *
 * setup.key.toString('hex') // -> 01d0…2516
 * derive.key.toString('hex') // -> 01d0…2516
 *
 * @param {Array.<MFKDFFactor>} factors - Array of factors used to derive this key
 * @param {Object} [options] - Configuration options
 * @param {string} [options.id='stack'] - Unique identifier for this factor
 * @param {number} [options.threshold] - Number of factors required to derive key; factors.length by default (all required)
 * @param {Buffer} [options.salt] - Cryptographic salt; generated via secure PRG by default (recommended)
 * @returns {MFKDFFactor} MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.15.0
 * @async
 * @memberof setup.factors
 */
async function stack (factors, options) {
  options = Object.assign(Object.assign({}, defaults.stack), options)

  if (typeof options.id !== 'string') {
    throw new TypeError('id must be a string')
  }
  if (options.id.length === 0) throw new RangeError('id cannot be empty')

  options.stack = true
  options.integrity = false

  const key = await setupKey(factors, options)

  return {
    type: 'stack',
    id: options.id,
    entropy: key.entropyBits.real,
    data: key.key,
    params: async () => {
      return key.policy
    },
    output: async () => {
      return key
    }
  }
}
module.exports.stack = stack
