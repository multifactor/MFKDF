/**
 * @file Multi-Factor Derived Key Persistence Functions
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Operations for persisting factors of a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

/**
  * Persist material from an MFKDF factor to bypass it in future derivation.
  * @param {string} id - id of the factor to persist
  * @returns {Buffer} - the share which can be used to bypass the factor
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.18.0
  */
function persistFactor (id) {
  const index = this.policy.factors.findIndex(x => x.id === id)
  return this.shares[index]
}
module.exports.persistFactor = persistFactor
