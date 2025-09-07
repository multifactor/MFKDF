/**
 * @file Key Derivation Function (KDF) Setup
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Validate and setup a KDF configuration for a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const defaults = require('../defaults')

/**
 * Validate and setup a KDF configuration for a multi-factor derived key
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
 * @param {Object} [options] - KDF configuration options
 * @param {string} [options.kdf='argon2id'] - KDF algorithm to use; hkdf, pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id
 * @param {string} [options.hkdfdigest='sha256'] - Hash function to use if using hkdf; sha1, sha256, sha384, or sha512
 * @param {number} [options.argon2time=2] - Iterations to use if using argon2
 * @param {number} [options.argon2mem=24576] - Memory to use if using argon2
 * @param {number} [options.argon2parallelism=1] - Parallelism to use if using argon2
 * @returns {object} A KDF configuration as a JSON object
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.7.0
 * @memberOf setup
 * @deprecated
 */
function kdf (options) {
  options = Object.assign(Object.assign({}, defaults.kdf), options)
  if (typeof options.kdf !== 'string') {
    throw new TypeError('kdf must be a string')
  }
  const config = {
    type: options.kdf,
    params: {}
  }

  if (options.kdf === 'hkdf') {
    // hdkf digest
    if (typeof options.hkdfdigest !== 'string') {
      throw new TypeError('hkdfdigest must be a string')
    }
    if (!['sha1', 'sha256', 'sha384', 'sha512'].includes(options.hkdfdigest)) {
      throw new RangeError(
        'hkdfdigest must be one of sha1, sha256, sha384, or sha512'
      )
    }
    config.params.digest = options.hkdfdigest
  } else if (
    options.kdf === 'argon2i' ||
    options.kdf === 'argon2d' ||
    options.kdf === 'argon2id'
  ) {
    // argon2 rounds
    if (!Number.isInteger(options.argon2time)) {
      throw new TypeError('argon2time must be an integer')
    }
    if (!(options.argon2time > 0)) {
      throw new RangeError('argon2time must be positive')
    }
    config.params.rounds = options.argon2time

    // argon2 memory
    if (!Number.isInteger(options.argon2mem)) {
      throw new TypeError('argon2mem must be an integer')
    }
    if (!(options.argon2mem > 0)) {
      throw new RangeError('argon2mem must be positive')
    }
    config.params.memory = options.argon2mem

    // argon2 parallelism
    if (!Number.isInteger(options.argon2parallelism)) {
      throw new TypeError('argon2parallelism must be an integer')
    }
    if (!(options.argon2parallelism > 0)) {
      throw new RangeError('argon2parallelism must be positive')
    }
    config.params.parallelism = options.argon2parallelism
  } else {
    throw new RangeError(
      'kdf must be one of hkdf, argon2i, argon2d, or argon2id'
    )
  }
  return config
}
module.exports.kdf = kdf
