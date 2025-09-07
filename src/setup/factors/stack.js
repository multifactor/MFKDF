/**
 * @file MFKDF Stack Factor Setup
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Setup key stacking factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const defaults = require('../../defaults')
const setupKey = require('../key').key

/**
 * Setup an MFKDF stacked key factor
 *
 * @example
 * // setup key with hmacsha1 factor
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.hmacsha1()
 * ], {size: 8})
 *
 * // calculate response; could be done using hardware device
 * const secret = setup.outputs.hmacsha1.secret
 * const challenge = Buffer.from(setup.policy.factors[0].params.challenge, 'hex')
 * const response = crypto.createHmac('sha1', secret).update(challenge).digest()
 *
 * // derive key with hmacsha1 factor
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   hmacsha1: mfkdf.derive.factors.hmacsha1(response)
 * })
 *
 * setup.key.toString('hex') // -> 01d0c7236adf2516
 * derive.key.toString('hex') // -> 01d0c7236adf2516
 *
 * @param {Array.<MFKDFFactor>} factors - Array of factors used to derive this key
 * @param {Object} [options] - Configuration options
 * @param {string} [options.id='stack'] - Unique identifier for this factor
 * @param {number} [options.size=32] - Size of derived key, in bytes
 * @param {number} [options.threshold] - Number of factors required to derive key; factors.length by default (all required)
 * @param {Buffer} [options.salt] - Cryptographic salt; generated via secure PRG by default (recommended)
 * @param {string} [options.kdf='pbkdf2'] - KDF algorithm to use; pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id
 * @param {number} [options.pbkdf2rounds=1] - Number of rounds to use if using pbkdf2
 * @param {string} [options.pbkdf2digest='sha256'] - Hash function to use if using pbkdf2; sha1, sha256, sha384, or sha512
 * @param {number} [options.bcryptrounds=10] - Number of rounds to use if using bcrypt
 * @param {number} [options.scryptcost=16384] - Iterations count (N) to use if using scrypt
 * @param {number} [options.scryptblocksize=8] - Block size (r) to use if using scrypt
 * @param {number} [options.scryptparallelism=1] - Parallelism factor (p) to use if using scrypt
 * @param {number} [options.argon2time=2] - Iterations to use if using argon2
 * @param {number} [options.argon2mem=24576] -Mmemory to use if using argon2
 * @param {number} [options.argon2parallelism=1] - Parallelism to use if using argon2
 * @returns {MFKDFFactor} MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.15.0
 * @async
 * @memberof setup.factors
 */
async function stack (factors, options) {
  options = Object.assign(Object.assign({}, defaults.stack), options)

  if (typeof options.id !== 'string') { throw new TypeError('id must be a string') }
  if (options.id.length === 0) throw new RangeError('id cannot be empty')

  const key = await setupKey(factors, options)

  return {
    type: 'stack',
    id: options.id,
    entropy: key.entropyBits.real,
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
