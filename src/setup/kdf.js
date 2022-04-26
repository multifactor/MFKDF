/**
 * @file Key Derivation Function (KDF) Setup
 * @copyright Multifactor 2022 All Rights Reserved
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
  * const config = await mfkdf.setup.kdf({
  *   kdf: 'pbkdf2',
  *   pbkdf2rounds: 100000,
  *   pbkdf2digest: 'sha256'
  * });
  *
  * @param {Object} [options] - KDF configuration options
  * @param {string} [options.kdf='argon2id'] - KDF algorithm to use; pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id
  * @param {number} [options.pbkdf2rounds=310000] - Number of rounds to use if using pbkdf2
  * @param {string} [options.pbkdf2digest='sha256'] - Hash function to use if using pbkdf2; sha1, sha256, sha384, or sha512
  * @param {number} [options.bcryptrounds=10] - Number of rounds to use if using bcrypt
  * @param {number} [options.scryptcost=16384] - Iterations count (N) to use if using scrypt
  * @param {number} [options.scryptblocksize=8] - Block size (r) to use if using scrypt
  * @param {number} [options.scryptparallelism=1] - Parallelism factor (p) to use if using scrypt
  * @param {number} [options.argon2time=2] - Iterations to use if using argon2
  * @param {number} [options.argon2mem=24576] - Memory to use if using argon2
  * @param {number} [options.argon2parallelism=1] - Parallelism to use if using argon2
  * @returns {object} A KDF configuration as a JSON object
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.7.0
  * @memberOf setup
  */
function kdf (options) {
  options = Object.assign(Object.assign({}, defaults.kdf), options)
  if (typeof options.kdf !== 'string') throw new TypeError('kdf must be a string')
  const config = {
    type: options.kdf,
    params: {}
  }
  if (options.kdf === 'pbkdf2') {
    // pbkdf2 rounds
    if (!(Number.isInteger(options.pbkdf2rounds))) throw new TypeError('pbkdf2rounds must be an integer')
    if (!(options.pbkdf2rounds > 0)) throw new RangeError('pbkdf2rounds must be positive')
    config.params.rounds = options.pbkdf2rounds

    // pbkdf2 digest
    if (typeof options.pbkdf2digest !== 'string') throw new TypeError('pbkdf2digest must be a string')
    if (!['sha1', 'sha256', 'sha384', 'sha512'].includes(options.pbkdf2digest)) throw new RangeError('pbkdf2digest must be one of sha1, sha256, sha384, or sha512')
    config.params.digest = options.pbkdf2digest
  } else if (options.kdf === 'bcrypt') {
    // bcrypt rounds
    if (!(Number.isInteger(options.bcryptrounds))) throw new TypeError('bcryptrounds must be an integer')
    if (!(options.bcryptrounds > 0)) throw new RangeError('bcryptrounds must be positive')
    config.params.rounds = options.bcryptrounds
  } else if (options.kdf === 'scrypt') {
    // scrypt rounds
    if (!(Number.isInteger(options.scryptcost))) throw new TypeError('scryptcost must be a positive integer')
    if (!(options.scryptcost > 0)) throw new RangeError('scryptcost must be positive')
    config.params.rounds = options.scryptcost

    // scrypt block size
    if (!(Number.isInteger(options.scryptblocksize))) throw new TypeError('scryptblocksize must be an integer')
    if (!(options.scryptblocksize > 0)) throw new RangeError('scryptblocksize must be positive')
    config.params.blocksize = options.scryptblocksize

    // scrypt parallelism
    if (!(Number.isInteger(options.scryptparallelism))) throw new TypeError('scryptparallelism must be an integer')
    if (!(options.scryptparallelism > 0)) throw new RangeError('scryptparallelism must be positive')
    config.params.parallelism = options.scryptparallelism
  } else if (options.kdf === 'argon2i' || options.kdf === 'argon2d' || options.kdf === 'argon2id') {
    // argon2 rounds
    if (!(Number.isInteger(options.argon2time))) throw new TypeError('argon2time must be an integer')
    if (!(options.argon2time > 0)) throw new RangeError('argon2time must be positive')
    config.params.rounds = options.argon2time

    // argon2 memory
    if (!(Number.isInteger(options.argon2mem))) throw new TypeError('argon2mem must be an integer')
    if (!(options.argon2mem > 0)) throw new RangeError('argon2mem must be positive')
    config.params.memory = options.argon2mem

    // argon2 parallelism
    if (!(Number.isInteger(options.argon2parallelism))) throw new TypeError('argon2parallelism must be an integer')
    if (!(options.argon2parallelism > 0)) throw new RangeError('argon2parallelism must be positive')
    config.params.parallelism = options.argon2parallelism
  } else {
    throw new RangeError('kdf must be one of pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id')
  }
  return config
}
module.exports.kdf = kdf
