/**
 * @file MFKDF Question Factor Derivation
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Derive question factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const zxcvbn = require('zxcvbn')

/**
 * Derive an MFKDF Security Question factor
 *
 * @example
 * // setup key with security question factor
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.question('Fido')
 * ], {size: 8})
 *
 * // derive key with security question factor
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   question: mfkdf.derive.factors.question('Fido')
 * })
 *
 * setup.key.toString('hex') // -> 01d0c7236adf2516
 * derive.key.toString('hex') // -> 01d0c7236adf2516
 *
 * @param {string} answer - The answer from which to derive an MFKDF factor
 * @returns {function(config:Object): Promise<MFKDFFactor>} Async function to generate MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 1.0.0
 * @memberof derive.factors
 */
function question (answer) {
  if (typeof answer !== 'string') throw new TypeError('answer must be a string')
  if (answer.length === 0) throw new RangeError('answer cannot be empty')

  answer = answer.toLowerCase().replace(/[^0-9a-z ]/gi, '').trim()
  const strength = zxcvbn(answer)

  return async (params) => {
    return {
      type: 'question',
      data: Buffer.from(answer),
      params: async () => {
        return params
      },
      output: async () => {
        return { strength }
      }
    }
  }
}
module.exports.question = question
