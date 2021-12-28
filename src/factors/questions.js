/**
 * @file MFKDF Security Question Factor
 * @copyright Multifactor 2021 All Rights Reserved
 *
 * @description
 * Security questions factor for multi-factor key derivation
 * (typically used as a recovery factor)
 *
 * WARNING: NIST SP 800-63 does not recommend using security
 * questions as an acceptable authentication factor for any
 * purpose, including account recovery.
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const config = require('../config')
const pbkdf2 = require('pbkdf2')

/**
 * Derive a MFKDF factor from a set of security questions & answers.
 *
 * @example
 * // derive a 128b MFKDF factor from three security question answers
 * const mfkdf = require('mfkdf');
 * const questionFactor = await mfkdf.factors.questions({
 *   'first-pet': 'max',
 *   'birth-city': 'jacksonville',
 *   'mother-maiden-name': 'smith'
 * }, {
 *   size: 16,
 *   digest: 'sha512'
 * })
 * console.log(questionFactor.toString('hex')) // 51fd94bc53fb8d1a9c1ca3bc1199a01b
 *
 * @param {Object} questions - The questions and answers from which to derive an MFKDF factor.
 * @param {Object} [options] - MFKDF factor configuration options
 * @param {number} [options.size=32] - size of key material to return, in bytes
 * @param {string} [options.digest=sha256] - hash function to use; see crypto.getHashes() for options
 * @param {string} [options.salt=''] - question salt to use; no salt is acceptable if overall MFKDF uses a salt
 * @param {boolean} [options.normalize=true] - sort by question and normalize answers to lowercase alphanumeric ascii (with spaces)
 * @returns Derived MFKDF key material as a Buffer.
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.3.0
 * @async
 */
module.exports.questions = async function questions (questions, options) {
  options = Object.assign(Object.assign({}, config.questionFactor), options)
  return new Promise((resolve, reject) => {
    questions = Object.entries(questions)
    if (options.normalize) {
      questions = questions.map(([key, value]) => {
        key = key.toLowerCase().replace(/[^0-9a-z-_ ]/g, '')
        value = value.toLowerCase().replace(/[^0-9a-z-_ ]/g, '')
        return [key, value]
      })
      questions.sort((a, b) => {
        if (a[0] < b[0]) return -1
        else if (a[0] > b[0]) return 1
        else return 0
      })
    }
    questions = questions.map(([key, value]) => key + ':' + value).join(';')

    pbkdf2.pbkdf2(questions, options.salt, 1, options.size, options.digest, (err, derivedKey) => {
      if (err) reject(err)
      else resolve(derivedKey)
    })
  })
}
