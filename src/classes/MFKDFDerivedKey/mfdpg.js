/**
 * @file Multi-Factor Derived Key Crypto Functions
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Multi-Factor Deterministic Password Generator (MFDPG2)
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const RandExp = require('randexp')
const rand = require('random-seed')

/**
 * Generate a policy-compliant password for a given purpose.
 *
 * @example
 *
 * @param {string} purpose - Unique purpose value for this password
 * @param {string} salt - Unique salt value for this salt
 * @param {string} regex - Regular expression defining password policy
 * @returns {string} Derived password
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 2.0.0
 * @memberOf MFKDFDerivedKey
 */
function derivePassword (purpose, salt, regex) {
  const passwordKey = this.getSubkey(purpose, salt)
  const dfa = new RandExp(regex)
  const rng = rand.create(passwordKey.toString('hex'))
  dfa.randInt = rng.intBetween
  return dfa.gen()
}
module.exports.derivePassword = derivePassword
