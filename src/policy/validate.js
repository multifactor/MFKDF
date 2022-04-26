/**
 * @file MFKDF Policy Validate
 * @copyright Multifactor 2022 All Rights Reserved
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
  * const ids = await mfkdf.policy.ids( ... );
  *
  * @param {Object} policy - Policy used to derive a key
  * @returns {Array.<string>} The ids of the provided factors
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.16.0
  * @memberOf policy
  */
function ids (policy) {
  let list = []
  for (const factor of policy.factors) {
    list.push(factor.id)
    if (factor.type === 'stack') list = list.concat(ids(factor.params))
  }
  return list
}
module.exports.ids = ids

/**
  * Validate multi-factor derived key policy
  *
  * @example
  * const result = await mfkdf.policy.validate( ... );
  *
  * @param {Object} policy - Policy used to derive a key
  * @returns {boolean} Whether the policy is valid
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.16.0
  * @memberOf policy
  */
function validate (policy) {
  const list = ids(policy)
  return ((new Set(list)).size === list.length)
}
module.exports.validate = validate
