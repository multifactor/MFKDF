/**
 * @file Key Derivation Function (KDF)
 * @copyright Multifactor 2021 All Rights Reserved
 *
 * @description
 * Implements several key derivation functions (KDFs) that can underly the MFKDF
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

// const argon2 = require('argon2-browser')

const { hkdfSync } = require('crypto')
const hash = require('hash-wasm')

/**
 * Single-factor (traditional) key derivation function; produces a derived a key from a single input.
 * Supports a number of underlying KDFs: pbkdf2, scrypt, bcrypt, and argon2 (recommended).
 *
 * @example
 * // setup kdf configuration
 * const config = await mfkdf.setup.kdf({
 * });
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
 * @deprecated
 */
async function kdf (input, salt, size, options) {
  if (typeof input === 'string') input = Buffer.from(input)
  if (typeof salt === 'string') salt = Buffer.from(salt)

  if (
    options.type === 'argon2i' ||
    options.type === 'argon2d' ||
    options.type === 'argon2id'
  ) {
    return new Promise((resolve, reject) => {
      let argon2 = hash.argon2id
      if (options.type === 'argon2i') argon2 = hash.argon2i
      else if (options.type === 'argon2d') argon2 = hash.argon2d
      argon2({
        password: input.toString(),
        salt: salt.toString(),
        iterations: options.params.rounds,
        memorySize: options.params.memory,
        hashLength: size,
        parallelism: options.params.parallelism,
        outputType: 'hex'
      }).then((result) => {
        resolve(Buffer.from(result, 'hex'))
      })
    })
  } else if (options.type === 'hkdf') {
    return new Promise((resolve, reject) => {
      return resolve(
        Buffer.from(hkdfSync(options.params.digest, input, salt, '', size))
      )
    })
  } else {
    throw new RangeError(
      'kdf should be one of hkdf, argon2i, argon2d, or argon2id (default)'
    )
  }
}
module.exports.kdf = kdf
