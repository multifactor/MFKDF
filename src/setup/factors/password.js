/**
 * @file MFKDF Password Factor Setup
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Setup password factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const defaults = require('../../defaults')
const zxcvbn = require('zxcvbn')

/**
 * Setup an MFKDF password factor
 *
 * @example
 * // setup key with password factor
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.password('password')
 * ])
 *
 * // derive key with password factor
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   password: mfkdf.derive.factors.password('password')
 * })
 *
 * setup.key.toString('hex') // -> 01d0…2516
 * derive.key.toString('hex') // -> 01d0…2516
 *
 * @param {string} password - The password from which to derive an MFKDF factor
 * @param {Object} [options] - Configuration options
 * @param {string} [options.id='password'] - Unique identifier for this factor
 * @returns {MFKDFFactor} MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.8.0
 * @async
 * @memberof setup.factors
 */
async function password (password, options) {
  if (typeof password !== 'string') {
    throw new TypeError('password must be a string')
  }
  if (password.length === 0) throw new RangeError('password cannot be empty')

  options = Object.assign(Object.assign({}, defaults.password), options)

  if (typeof options.id !== 'string') {
    throw new TypeError('id must be a string')
  }
  if (options.id.length === 0) throw new RangeError('id cannot be empty')

  const strength = zxcvbn(password)

  return {
    type: 'password',
    id: options.id,
    entropy: Math.log2(strength.guesses),
    data: Buffer.from(password, 'utf-8'),
    params: async () => {
      return {}
    },
    output: async () => {
      return { strength }
    }
  }
}
module.exports.password = password
