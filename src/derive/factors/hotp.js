/**
 * @file MFKDF HOTP Factor Derivation
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Derive HOTP factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const speakeasy = require('speakeasy')
const { decrypt } = require('../../crypt')

function mod (n, m) {
  return ((n % m) + m) % m
}

/**
 * Derive an MFKDF HOTP factor
 *
 * @example
 * // setup key with hotp factor
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.hotp({ secret: Buffer.from('abcdefghijklmnopqrst') })
 * ])
 *
 * // derive key with hotp factor
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   hotp: mfkdf.derive.factors.hotp(241063)
 * })
 *
 * setup.key.toString('hex') // -> 01d0c7236adf2516
 * derive.key.toString('hex') // -> 01d0c7236adf2516
 *
 * @param {number} code - The HOTP code from which to derive an MFKDF factor
 * @returns {function(config:Object): Promise<MFKDFFactor>} Async function to generate MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.12.0
 * @memberof derive.factors
 */
function hotp (code) {
  if (!Number.isInteger(code)) throw new TypeError('code must be an integer')

  return async (params) => {
    const target = mod(params.offset + code, 10 ** params.digits)
    const buffer = Buffer.allocUnsafe(4)
    buffer.writeUInt32BE(target, 0)

    return {
      type: 'hotp',
      data: buffer,
      params: async ({ key }) => {
        const pad = Buffer.from(params.pad, 'base64')
        const secret = decrypt(pad, key)

        const code = parseInt(
          speakeasy.hotp({
            secret: secret.subarray(0, 20).toString('hex'),
            encoding: 'hex',
            counter: params.counter + 1,
            algorithm: params.hash,
            digits: params.digits
          })
        )

        const offset = mod(target - code, 10 ** params.digits)

        return {
          hash: params.hash,
          digits: params.digits,
          pad: params.pad,
          counter: params.counter + 1,
          offset
        }
      },
      output: async () => {
        return {}
      }
    }
  }
}
module.exports.hotp = hotp
