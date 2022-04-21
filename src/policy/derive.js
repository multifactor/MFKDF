/**
 * @file MFKDF Policy Derivation
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Derive key from policy and given factors
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const validate = require('./validate').validate
const evaluate = require('./evaluate').evaluate
const stack = require('../derive/factors/stack').stack
const deriveKey = require('../derive/key').key

function expand(policy, factors) {
  const parsedFactors = {}
  const ids = Object.keys(factors)

  for (const factor of policy.factors) {
    if (factor.type === 'stack') {
      if (evaluate(factor.params, ids)) {
        parsedFactors[factor.id] = stack(expand(factor.params, factors))
      }
    } else {
      if (ids.includes(factor.id)) {
        parsedFactors[factor.id] = factors[factor.id];
      }
    }
  }

  return parsedFactors;
}

/**
 * Derive a policy-based multi-factor derived key
 *
 * @example
 * const key = await mfkdf.policy.derive( ... );
 *
 * @param {Object} policy - the key policy for the key being derived
 * @param {Object.<string, MFKDFFactor>} factors - factors used to derive this key
 * @returns {MFKDFDerivedKey} A multi-factor derived key object.
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.16.0
 * @async
 * @memberOf policy
 */
async function derive (policy, factors) {
  const ids = Object.keys(factors)
  if (!validate(policy)) throw new TypeError('policy contains duplicate ids')
  if (!evaluate(policy, ids)) throw new RangeError('insufficient factors to derive key')

  const expanded = expand(policy, factors)

  return await deriveKey(policy, expanded)
}
module.exports.derive = derive
