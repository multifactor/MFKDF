/**
 * @file MFKDF HOTP Factor Derivation
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Derive HOTP factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const xor = require('buffer-xor')
const speakeasy = require('speakeasy')

/**
 * Derive an MFKDF HOTP factor.
 *
 * @example
 * const HOTPFactor = mfkdf.derive.factors.password(...);
 *
 * @param {number} code - The HOTP code from which to derive an MFKDF factor.
 * @returns {function(config:Object): Promise<MFKDFFactor>} Async function to generate MFKDF factor information.
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.12.0
 * @memberof derive.factors
 */
function hotp (code) {
  if (!Number.isInteger(code)) throw new TypeError('code must be an integer')

  return async (params) => {
    const target = (params.offset + code) % (10 ** params.digits)
    const buffer = Buffer.allocUnsafe(4)
    buffer.writeUInt32BE(target, 0)

    return {
      type: 'hotp',
      data: buffer,
      params: async ({ key }) => {
        const pad = Buffer.from(params.pad, 'base64')
        const secret = xor(pad, key.slice(0, Buffer.byteLength(pad)))

        const code = parseInt(speakeasy.hotp({
          secret: secret.toString('hex'),
          encoding: 'hex',
          counter: params.counter + 1,
          algorithm: params.hash,
          digits: params.digits
        }))

        const offset = (target - code) % (10 ** params.digits)

        return {
          hash: params.hash,
          digits: params.digits,
          pad: params.pad,
          counter: params.counter + 1,
          offset
        }
      }
    }
  }
}
module.exports.hotp = hotp
