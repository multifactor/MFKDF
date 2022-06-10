/**
 * @file MFKDF OOBA Factor Derivation
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Derive Out-of-Band Authentication (OOBA) factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const crypto = require('crypto')
const xor = require('buffer-xor')
const random = require('random-number-csprng')

/**
 * Derive an MFKDF Out-of-Band Authentication (OOBA) factor
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
 * @param {number} code - The one-time code from which to derive an MFKDF factor
 * @returns {function(config:Object): Promise<MFKDFFactor>} Async function to generate MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 1.1.0
 * @memberof derive.factors
 */
function ooba (code) {
  if (typeof code !== 'string') throw new TypeError('code must be a string')
  code = code.toUpperCase()

  return async (params) => {
    const pad = Buffer.from(params.pad, 'base64')
    const target = xor(Buffer.from(code), pad)

    return {
      type: 'ooba',
      data: target,
      params: async ({ key }) => {
        let code = ''
        for (let i = 0; i < params.length; i++) {
          code += (await random(0, 35)).toString(36)
        }
        code = code.toUpperCase()
        const config = JSON.parse(JSON.stringify(params.params))
        config.code = code
        const pad = xor(Buffer.from(code), target)
        const plaintext = Buffer.from(JSON.stringify(config))
        const publicKey = await crypto.webcrypto.subtle.importKey('jwk', params.key, { name: 'RSA-OAEP', modulusLength: 2048, hash: 'SHA-256', publicExponent: new Uint8Array([0x01, 0x00, 0x01]) }, false, ['encrypt'])
        const ciphertext = await crypto.webcrypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, plaintext)
        return {
          length: params.length,
          key: params.key,
          params: params.params,
          next: Buffer.from(ciphertext).toString('hex'),
          pad: pad.toString('base64')
        }
      }
    }
  }
}
module.exports.ooba = ooba
