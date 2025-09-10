/**
 * @file MFKDF Question Factor Setup
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Setup question factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const defaults = require('../../defaults')
const zxcvbn = require('zxcvbn')

/**
 * Setup an MFKDF Security Question factor
 *
 * @example
 * // setup key with security question factor
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.question('Fido')
 * ])
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
 * @param {Object} [options] - Configuration options
 * @param {string} [options.question] - Security question corresponding to this factor
 * @param {string} [options.id='question'] - Unique identifier for this factor
 * @returns {MFKDFFactor} MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 1.0.0
 * @async
 * @memberof setup.factors
 */
async function question (answer, options) {
  options = Object.assign(Object.assign({}, defaults.question), options)
  if (typeof answer !== 'string') {
    throw new TypeError('answer must be a string')
  }
  if (answer.length === 0) throw new RangeError('answer cannot be empty')

  if (typeof options.id !== 'string') {
    throw new TypeError('id must be a string')
  }
  if (options.id.length === 0) throw new RangeError('id cannot be empty')

  if (typeof options.question === 'undefined') options.question = ''
  if (typeof options.question !== 'string') {
    throw new TypeError('question must be a string')
  }

  answer = answer
    .toLowerCase()
    .replace(/[^0-9a-z ]/gi, '')
    .trim()
  const strength = zxcvbn(answer)

  return {
    type: 'question',
    id: options.id,
    entropy: Math.log2(strength.guesses),
    data: Buffer.from(answer),
    params: async () => {
      return { question: options.question }
    },
    output: async () => {
      return { strength }
    }
  }
}
module.exports.question = question
