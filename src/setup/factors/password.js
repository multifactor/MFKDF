/**
 * @file MFKDF Password Factor Setup
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Setup password factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const defaults = require('../../defaults')

/**
 * Setup an MFKDF password factor.
 *
 * @example
 * const passwordFactor = mfkdf.setup.factors.password('password');
 *
 * @param {string} password - The password from which to derive an MFKDF factor.
 * @param {Object} [options] - configuration options
 * @param {string} [options.id] - unique identifier for this factor; 'password' default
 * @returns {MFKDFFactor} MFKDF factor information.
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.8.0
 * @async
 * @memberof setup.factors
 */
async function password (password, options) {
  if (typeof password !== 'string') throw new TypeError('password must be a string')
  if (password.length === 0) throw new RangeError('password cannot be empty')

  options = Object.assign(Object.assign({}, defaults.password), options)

  if (typeof options.id !== 'string') throw new TypeError('id must be a string')
  if (options.id.length === 0) throw new RangeError('id cannot be empty')

  return {
    type: 'password',
    id: options.id,
    data: Buffer.from(password, 'utf-8'),
    params: async () => {
      return {}
    },
    output: async () => {
      return {}
    }
  }
}
module.exports.password = password
