/**
 * @file MFKDF Policy Evaluation
 * @copyright Multifactor, Inc. 2022–2025
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
 * // setup key that can be derived from passwordA AND (passwordB OR passwordC)
 * const setup = await mfkdf.policy.setup(
 *   await mfkdf.policy.and(
 *     await mfkdf.setup.factors.password('passwordA', { id: 'passwordA' }),
 *     await mfkdf.policy.or(
 *       await mfkdf.setup.factors.password('passwordB', { id: 'passwordB' }),
 *       await mfkdf.setup.factors.password('passwordC', { id: 'passwordC' })
 *     )
 *   )
 * )
 *
 * // check if key can be derived with passwordA and passwordC
 * const valid1 = await mfkdf.policy.evaluate(setup.policy, ['passwordA', 'passwordC']) // -> true
 *
 * // check if key can be derived with passwordB and passwordC
 * const valid2 = await mfkdf.policy.evaluate(setup.policy, ['passwordB', 'passwordC']) // -> false
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
  return actual >= threshold
}
module.exports.evaluate = evaluate
