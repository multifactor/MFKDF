/**
 * @file Multi-Factor Derived Key Crypto Functions
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Cryptographic operations for a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const { hkdf } = require('../../crypt')

/**
 * Create a 256-bit sub-key for specified purpose using HKDF
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 *
 * // get sub-key for "eth"
 * const subkey = key.getSubkey('eth')
 * subkey.toString('hex') // -> 97cb…bac5
 *
 * @param {string} [purpose=''] - Unique purpose value for this sub-key
 * @param {string} [salt=''] - Unique salt value for this sub-key
 * @returns {Buffer} Derived sub-key
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.10.0
 * @memberOf MFKDFDerivedKey
 */
export async function getSubkey(purpose = '', salt = '') {
  return Buffer.from(await hkdf('sha256', this.key, salt, purpose, 32))
}
