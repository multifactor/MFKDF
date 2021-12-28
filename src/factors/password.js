/**
 * @file MFKDF Password Factor
 * @copyright Multifactor 2021 All Rights Reserved
 *
 * @description
 * Secure password factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const config = require('../config')
const pbkdf2 = require('pbkdf2')

/**
 * Derive a MFKDF factor from a password.
 *
 * @example
 * // derive a 512b MFKDF factor from a password using sha512
 * const mfkdf = require('mfkdf');
 * const passwordFactor = await mfkdf.factors.password('password', {
 *   size: 64,
 *   digest: 'sha512'
 * });
 *
 * @param {string} password - The password from which to derive an MFKDF factor.
 * @param {Object} [options] - MFKDF factor configuration options
 * @param {number} [options.size=32] - size of key material to return, in bytes
 * @param {string} [options.pdigest=sha256] - hash function to use; see crypto.getHashes() for options
 * @param {string} [options.salt=''] - password salt to use; no salt is acceptable if overall MFKDF uses a salt
 * @returns Derived MFKDF key material as a Buffer.
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.2.0
 * @async
 */
module.exports.password = function password (password, options) {
  options = Object.assign(Object.assign({}, config.passwordFactor), options)
  return new Promise((resolve, reject) => {
    pbkdf2.pbkdf2(password, options.salt, 1, options.size, options.digest, (err, derivedKey) => {
      if (err) reject(err)
      else resolve(derivedKey)
    })
  })
}
