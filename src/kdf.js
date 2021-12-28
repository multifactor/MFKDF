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
const scrypt = require('scrypt-js')
const argon2 = require('argon2-browser')

/**
  * Single-factor (traditional) key derivation function; produces a derived a key from a single input.
  * Supports a number of underlying KDFs: pbkdf2, scrypt, bcrypt, and argon2 (recommended).
  *
  * @example
  * // derive 256b key using pbkdf2-sha256 with 100,000 rounds
  * const mfkdf = require('mfkdf');
  * const key = await mfkdf.kdf('password', 'salt', {
  *   kdf: 'pbkdf2',
  *   size: 32,
  *   pbkdf2rounds: 100000,
  *   pbkdf2digest: 'sha256'
  * });
  *
  * @param {string} input - KDF input string
  * @param {string} salt - KDF salt string
  * @param {Object} [options] - KDF configuration options
  * @param {number} [options.size=32] - size of derived key to return, in bytes
  * @param {string} [options.kdf=argon2id] - KDF algorithm to use; one of pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id
  * @param {number} [options.pbkdf2rounds=310000] - number of rounds to use if using pbkdf2
  * @param {string} [options.pbkdf2digest=sha256] - hash function to use if using pbkdf2; see crypto.getHashes() for options
  * @param {number} [options.bcryptrounds=10] - number of rounds to use if using bcrypt
  * @param {number} [options.scryptcost=16384] - iterations count (N) to use if using scrypt
  * @param {number} [options.scryptblocksize=8] - block size (r) to use if using scrypt
  * @param {number} [options.scryptparallelism=1] - parallelism factor (p) to use if using scrypt
  * @param {number} [options.argon2time=2] - iterations to use if using argon2
  * @param {number} [options.argon2mem=24576] - memory to use if using argon2
  * @param {number} [options.argon2parallelism=24576] - parallelism to use if using argon2
  * @returns A derived key as a Buffer.
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
        else resolve(derivedKey)
      })
    })
  } else if (options.kdf === 'bcrypt') { // bcrypt
    if (options.bcryptrounds < 10) throw new RangeError('bcryptrounds must be at least 10')
    return new Promise((resolve, reject) => {
      // pre-hash to maximize entropy; safe when using base64 encoding
      const inputhash = crypto.createHash('sha256').update(input).digest('base64')
      const salthash = crypto.createHash('sha256').update(salt).digest('base64').replace(/\+/g, '.')

      // bcrypt with fixed salt
      bcrypt.hash(inputhash, '$2a$' + options.bcryptrounds + '$' + salthash, function (err, hash) {
        if (err) {
          reject(err)
        } else {
          // use pbkdf2/sha256 for stretching
          pbkdf2.pbkdf2(hash, salthash, 1, options.size, 'sha256', (err, derivedKey) => {
            if (err) reject(err)
            else resolve(derivedKey)
          })
        }
      })
    })
  } else if (options.kdf === 'scrypt') {
    return new Promise((resolve, reject) => {
      scrypt.scrypt(Buffer.from(input), Buffer.from(salt), options.scryptcost, options.scryptblocksize, options.scryptparallelism, options.size).then((result) => {
        resolve(Buffer.from(result))
      })
    })
  } else if (options.kdf === 'argon2i' || options.kdf === 'argon2d' || options.kdf === 'argon2id') {
    return new Promise((resolve, reject) => {
      let type = argon2.ArgonType.Argon2id
      if (options.kdf === 'argon2i') type = argon2.ArgonType.Argon2i
      else if (options.kdf === 'argon2d') type = argon2.ArgonType.Argon2d
      argon2.hash({ pass: input, salt: salt, time: options.argon2time, mem: options.argon2mem, hashLen: options.size, parallelism: options.argon2parallelism, type: type }).then((result) => {
        resolve(Buffer.from(result.hashHex, 'hex'))
      })
    })
  } else {
    throw new TypeError('kdf should be one of pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id (default)')
  }
}