/**
 * @file Key Derivation Function (KDF) Setup
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Validate and setup a KDF configuration for a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const config = require('../config')

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
  * @param {Object} [options] - KDF configuration options
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
  * @returns A KDF configuration as a JSON object.
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.7.0
  * @memberOf setup
  */
function kdf (options) {
  options = Object.assign(Object.assign({}, config.kdf), options)
  var config = {
    type: options.type,
    params: {}
  };
  if (options.kdf === 'pbkdf2') {
    config.params.rounds = options.pbkdf2rounds;
    config.params.digest = options.pbkdf2digest;
  } else if (options.kdf === 'bcrypt') {
    config.params.rounds = options.bcryptrounds;
  } else if (options.kdf === 'scrypt') {
    config.params.rounds = options.scryptcost;
    config.params.blocksize = options.scryptblocksize;
    config.params.parallelism = options.scryptparallelism;
  } else if (options.kdf === 'argon2i' || options.kdf === 'argon2d' || options.kdf === 'argon2id') {
    config.params.rounds = options.argon2time;
    config.params.memory = options.argon2mem;
    config.params.parallelism = options.argon2parallelism;
  } else {
    throw new TypeError('kdf should be one of pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id (default)')
  }
  return config;
}
module.exports.kdf = kdf
