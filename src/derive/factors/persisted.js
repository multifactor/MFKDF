/**
 * @file MFKDF Persisted Factor Derivation
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Use persisted factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

/**
 * Use a persisted MFDKF factor
 *
 * @example
 * // setup 3-factor multi-factor derived key
 * const setup = await mfkdf.setup.key([
 *  await mfkdf.setup.factors.password('password1', { id: 'password1' }),
 *  await mfkdf.setup.factors.password('password2', { id: 'password2' }),
 *  await mfkdf.setup.factors.password('password3', { id: 'password3' })
 * ], {size: 8})
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
 * setup.key.toString('hex') // -> 64587f2a0e65dc3c
 * derived.key.toString('hex') // -> 64587f2a0e65dc3c
 *
 * @param {Buffer} share - The share corresponding to the persisted factor
 * @returns {function(config:Object): Promise<MFKDFFactor>} Async function to generate MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.18.0
 * @memberof derive.factors
 */
function persisted (share) {
  if (!Buffer.isBuffer(share)) throw new TypeError('share must be a buffer')

  return async (params) => {
    return {
      type: 'persisted',
      data: share,
      params: async () => {
        return params
      }
    }
  }
}
module.exports.persisted = persisted
