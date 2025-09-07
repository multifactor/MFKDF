/**
 * @file MFKDF Policy Validate
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Determine whether key can be derived from given factors
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

/**
 * Get all ids of multi-factor derived key factors (including factors of stacked keys)
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
 * // get list of ids
 * const ids = mfkdf.policy.ids(setup.policy) // -> ['passwordA', 'passwordB', 'passwordC', ...]
 *
 * @param {Object} policy - Policy used to derive a key
 * @returns {Array.<string>} The ids of the provided factors
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.16.0
 * @memberOf policy
 */
function ids(policy) {
  let list = [];
  for (const factor of policy.factors) {
    list.push(factor.id);
    if (factor.type === "stack") list = list.concat(ids(factor.params));
  }
  return list;
}
module.exports.ids = ids;

/**
 * Validate multi-factor derived key policy
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
 * // validate policy
 * const valid = mfkdf.policy.validate(setup.policy) // -> true
 *
 * @param {Object} policy - Policy used to derive a key
 * @returns {boolean} Whether the policy is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.16.0
 * @memberOf policy
 */
function validate(policy) {
  const list = ids(policy);
  return new Set(list).size === list.length;
}
module.exports.validate = validate;
