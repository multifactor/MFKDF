/**
 * @file Multi-Factor Derived Key Crypto Functions
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Cryptographic operations for a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const { hkdfSync } = require('crypto')

/**
 * Create a 256-bit sub-key for specified purpose using HKDF
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 *
 * // get sub-key for "eth"
 * const subkey = key.getSubkey('eth')
 * subkey.toString('hex') // -> 97cbb79f622ef8fcc86ab5e06fc0311377b1e59d6f43b0c24883c38fe8bcbac5
 *
 * @param {string} [purpose=''] - Unique purpose value for this sub-key
 * @param {string} [salt=''] - Unique salt value for this sub-key
 * @returns {Buffer} Derived sub-key
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.10.0
 * @memberOf MFKDFDerivedKey
 */
function getSubkey (purpose = '', salt = '') {
  return Buffer.from(hkdfSync('sha256', this.key, salt, purpose, 32))
}
module.exports.getSubkey = getSubkey
