/**
 * @file Key Derivation Function (KDF)
 * @copyright Multifactor 2021 All Rights Reserved
 *
 * @description
 * Implements several key derivation functions (KDFs) that can underly the MFKDF
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const crypto = require('crypto')
const pbkdf2 = require('pbkdf2')
const bcrypt = require('bcryptjs')
const scrypt = require('scrypt-js')
const argon2 = require('argon2-browser')
const { hkdf } = require('@panva/hkdf')

/**
 * Single-factor (traditional) key derivation function; produces a derived a key from a single input.
 * Supports a number of underlying KDFs: pbkdf2, scrypt, bcrypt, and argon2 (recommended).
 *
 * @example
 * // setup kdf configuration
 * const config = await mfkdf.setup.kdf({
 *   kdf: 'pbkdf2',
 *   pbkdf2rounds: 100000,
 *   pbkdf2digest: 'sha256'
 * }); // -> { type: 'pbkdf2', params: { rounds: 100000, digest: 'sha256' } }
 *
 * // derive key
 * const key = await mfkdf.kdf('password', 'salt', 8, config);
 * key.toString('hex') // -> 0394a2ede332c9a1
 *
 * @param {Buffer|string} input - KDF input string
 * @param {Buffer|string} salt - KDF salt string
 * @param {number} size - Size of derived key to return, in bytes
 * @param {Object} options - KDF configuration options
 * @param {string} options.type - KDF algorithm to use; hkdf, pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id
 * @param {Object} options.params - Specify parameters of chosen kdf
 * @param {number} options.params.rounds - Number of rounds to use
 * @param {number} [options.params.digest] - Hash function to use (if using pbkdf2 or hdkf)
 * @param {number} [options.params.blocksize] - Block size to use (if using scrypt)
 * @param {number} [options.params.parallelism] - Parallelism to use (if using scrypt or argon2)
 * @param {number} [options.params.memory] - Memory to use (if using argon2)
 * @returns A derived key as a Buffer
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.0.3
 * @async
 * @memberOf kdfs
 */
async function kdf (input, salt, size, options) {
  if (typeof input === 'string') input = Buffer.from(input)
  if (typeof salt === 'string') salt = Buffer.from(salt)

  if (options.type === 'pbkdf2') { // PBKDF2
    return new Promise((resolve, reject) => {
      pbkdf2.pbkdf2(input, salt, options.params.rounds, size, options.params.digest, (err, derivedKey) => {
        /* istanbul ignore if */
        if (err) reject(err)
        else resolve(derivedKey)
      })
    })
  } else if (options.type === 'bcrypt') { // bcrypt
    return new Promise((resolve, reject) => {
      // pre-hash to maximize entropy; safe when using base64 encoding
      const inputhash = crypto.createHash('sha256').update(input).digest('base64')
      const salthash = crypto.createHash('sha256').update(salt).digest('base64').replace(/\+/g, '.')

      // bcrypt with fixed salt
      bcrypt.hash(inputhash, '$2a$' + options.params.rounds + '$' + salthash, function (err, hash) {
        /* istanbul ignore if */
        if (err) {
          reject(err)
        } else {
          // use pbkdf2/sha256 for stretching
          pbkdf2.pbkdf2(hash, salthash, 1, size, 'sha256', (err, derivedKey) => {
            /* istanbul ignore if */
            if (err) reject(err)
            else resolve(derivedKey)
          })
        }
      })
    })
  } else if (options.type === 'scrypt') {
    return new Promise((resolve, reject) => {
      scrypt.scrypt(input, salt, options.params.rounds, options.params.blocksize, options.params.parallelism, size).then((result) => {
        resolve(Buffer.from(result))
      })
    })
  } else if (options.type === 'argon2i' || options.type === 'argon2d' || options.type === 'argon2id') {
    return new Promise((resolve, reject) => {
      let type = argon2.ArgonType.Argon2id
      if (options.type === 'argon2i') type = argon2.ArgonType.Argon2i
      else if (options.type === 'argon2d') type = argon2.ArgonType.Argon2d
      argon2.hash({ pass: input.toString(), salt: salt.toString(), time: options.params.rounds, mem: options.params.memory, hashLen: size, parallelism: options.params.parallelism, type }).then((result) => {
        resolve(Buffer.from(result.hashHex, 'hex'))
      })
    })
  } if (options.type === 'hkdf') {
    return new Promise((resolve, reject) => {
      hkdf(options.params.digest, input, salt, '', size).then((result) => {
        resolve(Buffer.from(result))
      })
    })
  } else {
    throw new RangeError('kdf should be one of pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id (default)')
  }
}
module.exports.kdf = kdf
