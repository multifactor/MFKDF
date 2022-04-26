/**
 * @file MFKDF Stack Factor Derivation
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Derive key stacking factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const deriveKey = require('../key').key

/**
 * Derive an MFKDF stacked key factor
 *
 * @example
 * const stackFactor = mfkdf.derive.factors.stack(...);
 *
 * @param {Object.<string, MFKDFFactor>} factors - Factors used to derive this key
 * @returns {function(config:Object): Promise<MFKDFFactor>} Async function to generate MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.15.0
 * @memberof derive.factors
 */
function stack (factors) {
  return async (params) => {
    const key = await deriveKey(params, factors)

    return {
      type: 'stack',
      data: key.key,
      params: async () => {
        return key.policy
      }
    }
  }
}
module.exports.stack = stack
