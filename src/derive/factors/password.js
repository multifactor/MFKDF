/**
 * @file MFKDF Password Factor Derivation
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Derive password factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

/**
 * Derive an MFKDF password factor.
 *
 * @example
 * const passwordFactor = mfkdf.derive.factors.password('password');
 *
 * @param {string} password - The password from which to derive an MFKDF factor.
 * @returns {(config:Object) => Promise<MFKDFFactor>} Async function to generate MFKDF factor information.
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.10.0
 * @memberof derive.factors
 */
function password (password) {
  if (typeof password !== 'string') throw new TypeError('password must be a string')
  if (password.length === 0) throw new RangeError('password cannot be empty')

  return async () => {
    return {
      type: 'password',
      data: Buffer.from(password, 'utf-8'),
      params: async () => {
        return {}
      }
    }
  }
}
module.exports.password = password
