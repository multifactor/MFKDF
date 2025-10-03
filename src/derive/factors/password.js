/**
 * @file MFKDF Password Factor Derivation
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Derive password factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const zxcvbn = require('zxcvbn')

/**
 * Derive an MFKDF password factor
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
 * @returns {function(config:Object): Promise<MFKDFFactor>} Async function to generate MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.9.0
 * @memberof derive.factors
 */
function password(password) {
  if (typeof password !== 'string') {
    throw new TypeError('password must be a string')
  }
  if (password.length === 0) throw new RangeError('password cannot be empty')

  const strength = zxcvbn(password)

  return async () => {
    return {
      type: 'password',
      data: Buffer.from(password, 'utf-8'),
      params: async () => {
        return {}
      },
      output: async () => {
        return { strength }
      }
    }
  }
}
export { password }
