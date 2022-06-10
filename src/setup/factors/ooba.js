/**
 * @file MFKDF OOBA Factor Setup
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Setup an Out-of-Band Authentication (OOBA) factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const defaults = require('../../defaults')
const crypto = require('crypto')
const xor = require('buffer-xor')

/**
 * Setup an MFKDF Out-of-Band Authentication (OOBA) factor
 *
 * @example
 * // setup RSA key pair (on out-of-band server)
 * const keyPair = await crypto.webcrypto.subtle.generateKey({hash: 'SHA-256', modulusLength: 2048, name: 'RSA-OAEP', publicExponent: new Uint8Array([1, 0, 1])}, true, ['encrypt', 'decrypt'])
 *
 * // setup key with out-of-band authentication factor
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.ooba({
 *     key: keyPair.publicKey, params: { email: 'test@mfkdf.com' }
 *   })
 * ])
 *
 * // decrypt and send code (on out-of-band server)
 * const next = setup.policy.factors[0].params.next
 * const decrypted = await crypto.webcrypto.subtle.decrypt({name: 'RSA-OAEP'}, keyPair.privateKey, Buffer.from(next, 'hex'))
 * const code = JSON.parse(Buffer.from(decrypted).toString()).code;
 *
 * // derive key with out-of-band factor
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   ooba: mfkdf.derive.factors.ooba(code)
 * })
 *
 * setup.key.toString('hex') // -> 01d0c7236adf2516
 * derive.key.toString('hex') // -> 01d0c7236adf2516
 *
 * @param {Object} [options] - Configuration options
 * @param {string} [options.id='ooba'] - Unique identifier for this factor
 * @param {number} [options.length=6] - Number of characters to use in one-time codes
 * @param {CryptoKey} options.key - Public key of out-of-band channel
 * @param {Object} options.params - Parameters to provide out-of-band channel
 * @returns {MFKDFFactor} MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 1.1.0
 * @async
 * @memberof setup.factors
 */
async function ooba (options) {
  options = Object.assign(Object.assign({}, defaults.ooba), options)
  if (typeof options.id !== 'string') throw new TypeError('id must be a string')
  if (options.id.length === 0) throw new RangeError('id cannot be empty')
  if (!Number.isInteger(options.length)) throw new TypeError('length must be an interger')
  if (options.length <= 0) throw new RangeError('length must be positive')
  if (options.length > 32) throw new RangeError('length must be at most 32')
  if (options.key.type !== "public") throw new TypeError('key must be a public CryptoKey')
  if (typeof options.params !== 'object') throw new TypeError('params must be an object')

  const target = crypto.randomBytes(options.length)

  return {
    type: 'ooba',
    id: options.id,
    data: target,
    entropy: Math.log2(36 ** options.length),
    params: async ({ key }) => {
      let code = ''
      for (let i = 0; i < options.length; i++) {
        code += crypto.randomInt(0, 36).toString(36)
      }
      code = code.toUpperCase()
      const params = JSON.parse(JSON.stringify(options.params))
      params.code = code
      const pad = xor(Buffer.from(code), target)
      const plaintext = Buffer.from(JSON.stringify(params))
      const ciphertext = await crypto.webcrypto.subtle.encrypt({ name: 'RSA-OAEP' }, options.key, plaintext)
      const jwk = await crypto.webcrypto.subtle.exportKey('jwk', options.key)
      return {
        length: options.length,
        key: jwk,
        params: options.params,
        next: Buffer.from(ciphertext).toString('hex'),
        pad: pad.toString('base64')
      }
    },
    output: async () => {
      return {

      }
    }
  }
}
module.exports.ooba = ooba
