/**
 * @file MFKDF Stack Factor Setup
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Setup key stacking factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const defaults = require('../../defaults')
const setupKey = require('../key').key

/**
 * Setup an MFKDF stacked key factor.
 *
 * @example
 * const stackFactor = mfkdf.setup.factors.stack(...);
 *
 * @param {Array.<MFKDFFactor>} factors - array of factors used to derive this key
 * @param {Object} [options] - configuration options
 * @param {string} [options.id] - unique identifier for this factor; 'stack' by default
 * @param {number} [options.size=32] - size of derived key, in bytes
 * @param {number} [options.threshold] - number of factors required to derive key; factors.length by default (all required)
 * @param {Buffer} [options.salt] - cryptographic salt; generated via secure PRG by default (recommended)
 * @param {string} [options.kdf=pbkdf2] - KDF algorithm to use; one of pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id
 * @param {number} [options.pbkdf2rounds=1] - number of rounds to use if using pbkdf2
 * @param {string} [options.pbkdf2digest=sha256] - hash function to use if using pbkdf2; one of sha1, sha256, sha384, or sha512
 * @param {number} [options.bcryptrounds=10] - number of rounds to use if using bcrypt
 * @param {number} [options.scryptcost=16384] - iterations count (N) to use if using scrypt
 * @param {number} [options.scryptblocksize=8] - block size (r) to use if using scrypt
 * @param {number} [options.scryptparallelism=1] - parallelism factor (p) to use if using scrypt
 * @param {number} [options.argon2time=2] - iterations to use if using argon2
 * @param {number} [options.argon2mem=24576] - memory to use if using argon2
 * @param {number} [options.argon2parallelism=24576] - parallelism to use if using argon2
 * @returns {MFKDFFactor} MFKDF factor information.
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.15.0
 * @async
 * @memberof setup.factors
 */
async function stack (factors, options) {
  options = Object.assign(Object.assign({}, defaults.stack), options)

  if (typeof options.id !== 'string') throw new TypeError('id must be a string')
  if (options.id.length === 0) throw new RangeError('id cannot be empty')

  const key = await setupKey(factors, options)

  return {
    type: 'stack',
    id: options.id,
    data: key.key,
    params: async () => {
      return key.policy
    },
    output: async () => {
      return key
    }
  }
}
module.exports.stack = stack
