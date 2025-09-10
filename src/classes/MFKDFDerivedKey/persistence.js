/**
 * @file Multi-Factor Derived Key Persistence Functions
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Operations for persisting factors of a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

/**
 * Persist material from an MFKDF factor to bypass it in future derivation
 *
 * @example
 * // setup 3-factor multi-factor derived key
 * const setup = await mfkdf.setup.key([
 *  await mfkdf.setup.factors.password('password1', { id: 'password1' }),
 *  await mfkdf.setup.factors.password('password2', { id: 'password2' }),
 *  await mfkdf.setup.factors.password('password3', { id: 'password3' })
 * ])
 *
 * // persist one of the factors
 * const factor2 = setup.persistFactor('password2')
 *
 * // derive key with 2 factors
 * const derived = await mfkdf.derive.key(setup.policy, {
 *  password1: mfkdf.derive.factors.password('password1'),
 *  password2: mfkdf.derive.factors.persisted(factor2),
 *  password3: mfkdf.derive.factors.password('password3')
 * })
 *
 * setup.key.toString('hex') // -> 6458…dc3c
 * derived.key.toString('hex') // -> 6458…dc3c
 *
 * @param {string} id - ID of the factor to persist
 * @returns {Buffer} - The share which can be used to bypass the factor
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.18.0
 * @memberOf MFKDFDerivedKey
 */
function persistFactor (id) {
  const index = this.policy.factors.findIndex((x) => x.id === id)
  return this.shares[index]
}
module.exports.persistFactor = persistFactor
