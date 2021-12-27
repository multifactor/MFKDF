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
const crypto = require('crypto')
const pbkdf2 = require('pbkdf2')
const bcrypt = require('bcryptjs')

/**
  * Single-factor (traditional) key derivation function; produces a derived a key from a single input.
  * Supports a number of underlying KDFs: pbkdf2, scrypt, bcrypt, and argon2 (recommended).
  *
  * @example
  * const key = await kdf();
  *
  * @param {string} input - KDF input string
  * @param {string} salt - KDF salt string
  * @param {Object} options - KDF options
  * @param {string} [options.kdf=argon2] - KDF algorithm to use; one of pbkdf2, scrypt, bcrypt, or argon2 (default).
  * @returns A derived key as a hex-encoded string.
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.0.3
  * @async
  */
module.exports.kdf = async function kdf (input, salt, options) {
  if (typeof input !== 'string') throw new TypeError('input must be a string')
  if (typeof salt !== 'string') throw new TypeError('salt must be a string')

  options = Object.assign(Object.assign({}, config.kdf), options)
  if (options.kdf === 'pbkdf2') { // PBKDF2
    return new Promise((resolve, reject) => {
      pbkdf2.pbkdf2(input, salt, options.pbkdf2rounds, options.size, options.pbkdf2digest, (err, derivedKey) => {
        if (err) reject(err)
        else resolve(derivedKey.toString('hex'))
      })
    })
  } else if (options.kdf === 'bcrypt') { // bcrypt
    if (options.bcryptrounds < 10) throw new RangeError('bcryptrounds must be at least 10')
    return new Promise((resolve, reject) => {
      // pre-hash to maximize entropy; safe when using base64 encoding
      const inputhash = crypto.createHash('sha256').update(input).digest('base64')
      const salthash = crypto.createHash('sha256').update(salt).digest('base64').replace(/\+/g, '.')

      // bcrypt with fixed hash
      bcrypt.hash(inputhash, '$2a$' + options.bcryptrounds + '$' + salthash, function (err, hash) {
        if (err) {
          reject(err)
        } else {
          // use pbkdf2/sha256 for stretching
          pbkdf2.pbkdf2(hash, salthash, 1, options.size, 'sha256', (err, derivedKey) => {
            if (err) reject(err)
            else resolve(derivedKey.toString('hex'))
          })
        }
      })
    })
  } else {
    throw new TypeError('kdf should be one of pbkdf2, scrypt, bcrypt, or argon2 (default)')
  }
}
