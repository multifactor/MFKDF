/**
 * @file Key Derivation Function (KDF)
 * @copyright Multifactor 2021 All Rights Reserved
 *
 * @description
 * Implements several key derivation functions (KDFs) that can underly the MFKDF
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const config = require('./config')
const pbkdf2 = require('pbkdf2')

/**
  * Single-factor (traditional) key derivation function; produces a derived a key from a single input.
  * Supports a number of underlying KDFs: pbkdf2, scrypt, bcrypt, and argon2 (recommended).
  *
  * @example
  * const key = await kdf();
  *
  * @param {string} input - KDF input.
  * @param {string} [options.kdf=argon2] - KDF algorithm to use; one of pbkdf2, scrypt, bcrypt, or argon2 (default).
  * @returns A derived key as a hex-encoded string.
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.0.3
  * @async
  */
module.exports.kdf = async function kdf (input, options) {
  options = Object.assign(Object.assign({}, config.kdf), options)
  if (options.kdf === 'pbkdf2') {
    return new Promise((resolve, reject) => {
      pbkdf2.pbkdf2(input, options.salt, options.pbkdf2rounds, options.size, options.pbkdf2digest, (err, derivedKey) => {
        if (err) reject(err)
        resolve(derivedKey.toString('hex'))
      })
    })
  } else {
    throw new TypeError('kdf should be one of pbkdf2, scrypt, bcrypt, or argon2 (default)')
  }
}
