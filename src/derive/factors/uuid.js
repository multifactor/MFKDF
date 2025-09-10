/**
 * @file MFKDF UUID Factor Derivation
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Derive UUID factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const { validate: uuidValidate, parse: uuidParse } = require('uuid')

/**
 * Derive an MFKDF UUID factor
 *
 * @example
 * // setup key with uuid factor
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.uuid({ uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
 * ])
 *
 * // derive key with uuid factor
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   uuid: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
 * })
 *
 * setup.key.toString('hex') // -> 01d0…2516
 * derive.key.toString('hex') // -> 01d0…2516
 *
 * @param {string} uuid - The uuid from which to derive an MFKDF factor
 * @returns {function(config:Object): Promise<MFKDFFactor>} Async function to generate MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.9.0
 * @memberof derive.factors
 */
function uuid (uuid) {
  if (typeof uuid !== 'string') throw new TypeError('uuid must be a string')
  if (!uuidValidate(uuid)) throw new TypeError('uuid is not a valid uuid')

  return async () => {
    return {
      type: 'uuid',
      data: Buffer.from(uuidParse(uuid)),
      params: async () => {
        return {}
      },
      output: async () => {
        return { uuid }
      }
    }
  }
}
module.exports.uuid = uuid
