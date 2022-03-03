/**
 * @file MFKDF HOTP Factor
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Secure HOTP factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const config = require('../config')
const pbkdf2 = require('pbkdf2')

/**
 * Derive a MFKDF factor from an HOTP code.
 *
 * @example
 * // derive a 512b MFKDF factor from an HOTP code using sha512
 * const mfkdf = require('mfkdf');
 * const hotpFactor = await mfkdf.factors.hotp(000000, 123456, {
 *   size: 64,
 *   digest: 'sha512'
 * });
 *
 * @param {number} code - The HOTP code from which to derive an MFKDF factor.
 * @param {number} offset - The HOTP offset from which to derive an MFKDF factor.
 * @param {Object} [options] - MFKDF factor configuration options
 * @param {number} [options.size=32] - size of key material to return, in bytes
 * @param {string} [options.digest=sha256] - hash function to use; see crypto.getHashes() for options
 * @param {string} [options.salt=''] - salt to use; no salt is acceptable if overall MFKDF uses a salt
 * @returns Derived MFKDF key material as a Buffer.
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.5.0
 * @async
 * @memberof factors
 */
async function hotp (code, offset, options) {
  options = Object.assign(Object.assign({}, config.passwordFactor), options)
  return new Promise((resolve, reject) => {
    pbkdf2.pbkdf2(Buffer.from(((code + offset) % 1000000).toString()), options.salt, 1, options.size, options.digest, (err, derivedKey) => {
      if (err) reject(err)
      else resolve(derivedKey)
    })
  })
}
module.exports.hotp = hotp
