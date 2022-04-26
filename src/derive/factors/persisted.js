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
 * const persistedFactor = mfkdf.derive.factors.persisted(...);
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
