/**
 * @file MFKDF Policy Evaluation
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Determine whether key can be derived from given factors
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

/**
  * Evaluate a policy-based multi-factor derived key
  *
  * @example
  * const result = await mfkdf.policy.evaluate( ... );
  *
  * @param {Object} policy - The key policy for the key being derived
  * @param {Array.<string>} factors - Array of factor ids used to derive this key
  * @returns {boolean} Whether the key can be derived with given factor ids
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.16.0
  * @memberOf policy
  */
function evaluate (policy, factors) {
  const threshold = policy.threshold
  let actual = 0
  for (const factor of policy.factors) {
    if (factor.type === 'stack') {
      if (evaluate(factor.params, factors)) actual++
    } else {
      if (factors.includes(factor.id)) actual++
    }
  }
  return (actual >= threshold)
}
module.exports.evaluate = evaluate
