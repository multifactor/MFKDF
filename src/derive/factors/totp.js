/**
 * @file MFKDF TOTP Factor Derivation
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Derive TOTP factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const xor = require('buffer-xor')
const speakeasy = require('speakeasy')

function mod (n, m) {
  return ((n % m) + m) % m
}

/**
 * Derive an MFKDF TOTP factor
 *
 * @example
 * // setup key with totp factor
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.totp({
 *     secret: Buffer.from('hello world'),
 *     time: 1650430806597
 *   })
 * ], {size: 8})
 *
 * // derive key with totp factor
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   totp: mfkdf.derive.factors.totp(528258, { time: 1650430943604 })
 * })
 *
 * setup.key.toString('hex') // -> 01d0c7236adf2516
 * derive.key.toString('hex') // -> 01d0c7236adf2516
 *
 * @param {number} code - The TOTP code from which to derive an MFKDF factor
 * @param {Object} [options] - Additional options for deriving the TOTP factor
 * @param {number} [options.time] - Current time for TOTP; defaults to Date.now()
 * @returns {function(config:Object): Promise<MFKDFFactor>} Async function to generate MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.13.0
 * @memberof derive.factors
 */
function totp (code, options = {}) {
  if (!Number.isInteger(code)) throw new TypeError('code must be an integer')
  if (typeof options.time === 'undefined') options.time = Date.now()
  if (!Number.isInteger(options.time)) { throw new TypeError('time must be an integer') }
  if (options.time <= 0) throw new RangeError('time must be positive')

  return async (params) => {
    const offsets = Buffer.from(params.offsets, 'base64')
    const startCounter = Math.floor(params.start / (params.step * 1000))
    const nowCounter = Math.floor(options.time / (params.step * 1000))

    const index = nowCounter - startCounter

    if (index >= params.window) throw new RangeError('TOTP window exceeded')

    const offset = offsets.readUInt32BE(4 * index)

    const target = mod(offset + code, 10 ** params.digits)
    const buffer = Buffer.allocUnsafe(4)
    buffer.writeUInt32BE(target, 0)

    return {
      type: 'totp',
      data: buffer,
      params: async ({ key }) => {
        const pad = Buffer.from(params.pad, 'base64')
        const secret = xor(pad, key.slice(0, Buffer.byteLength(pad)))

        const time = options.time
        const newOffsets = Buffer.allocUnsafe(4 * params.window)

        offsets.copy(newOffsets, 0, 4 * index)

        for (let i = params.window - index; i < params.window; i++) {
          const counter = Math.floor(time / (params.step * 1000)) + i

          const code = parseInt(
            speakeasy.totp({
              secret: secret.toString('hex'),
              encoding: 'hex',
              step: params.step,
              counter,
              algorithm: params.hash,
              digits: params.digits
            })
          )

          const offset = mod(target - code, 10 ** params.digits)

          newOffsets.writeUInt32BE(offset, 4 * i)
        }

        return {
          start: time,
          hash: params.hash,
          digits: params.digits,
          step: params.step,
          window: params.window,
          pad: params.pad,
          offsets: newOffsets.toString('base64')
        }
      },
      output: async () => {
        return {}
      }
    }
  }
}
module.exports.totp = totp
