/**
 * @file MFKDF Password Factor Setup
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Setup password factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

/**
 * Setup an MFKDF password factor.
 *
 * @example
 * const passwordFactor = mfkdf.setup.factors.password('password');
 *
 * @param {string} password - The password from which to derive an MFKDF factor.
 * @returns {MFKDFFactor} MFKDF factor information.
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.8.0
 * @async
 * @memberof setup.factors
 */
async function password (password) {
  if (typeof password !== 'string') throw new TypeError('password must be a string')
  if (password.length === 0) throw new RangeError('password cannot be empty')

  return {
    type: 'password',
    data: Buffer.from(password, 'utf-8'),
    params: async () => {
      return {}
    }
  }
}
module.exports.password = password
