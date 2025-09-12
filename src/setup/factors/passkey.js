/**
 * @file MFKDF Passkey Factor Setup
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Setup passkey factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

/**
 * Setup an MFKDF passkey factor
 *
 * @example
 *
 * @param {Buffer} secret - The 256-bit PRF secret from which to derive an MFKDF factor
 * @param {Object} [options] - Configuration options
 * @param {string} [options.id='passkey'] - Unique identifier for this factor
 * @returns {MFKDFFactor} MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 2.0.0
 * @async
 * @memberof setup.factors
 */
async function passkey (secret, options) {
  if (!Buffer.isBuffer(secret)) {
    throw new TypeError('secret must be a Buffer')
  }
  if (Buffer.byteLength(secret) !== 32) {
    throw new RangeError('secret must be 32 bytes (256 bits) in length')
  }

  options = Object.assign({}, options)

  if (options.id === undefined) options.id = 'passkey'
  if (typeof options.id !== 'string') {
    throw new TypeError('id must be a string')
  }
  if (options.id.length === 0) throw new RangeError('id cannot be empty')

  return {
    type: 'passkey',
    id: options.id,
    entropy: 256,
    data: secret,
    params: async () => {
      return {}
    },
    output: async () => {
      return {}
    }
  }
}
module.exports.passkey = passkey
