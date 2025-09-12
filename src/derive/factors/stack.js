/**
 * @file MFKDF Stack Factor Derivation
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Derive key stacking factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const deriveKey = require("../key").key;

/**
 * Derive an MFKDF stacked key factor
 *
 * @example
 * // setup key with stack factor
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.stack([
 *     await mfkdf.setup.factors.password('password1', {
 *       id: 'password1'
 *     }),
 *     await mfkdf.setup.factors.password('password2', {
 *       id: 'password2'
 *     })
 *   ]),
 *   await mfkdf.setup.factors.password('password3', { id: 'password3' })
 * ])
 *
 * // derive key with stack factor
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   stack: mfkdf.derive.factors.stack({
 *     password1: mfkdf.derive.factors.password('password1'),
 *     password2: mfkdf.derive.factors.password('password2')
 *   }),
 *   password3: mfkdf.derive.factors.password('password3')
 * })
 *
 * setup.key.toString('hex') // -> 01d0…2516
 * derive.key.toString('hex') // -> 01d0…2516
 *
 * @param {Object.<string, MFKDFFactor>} factors - Factors used to derive this key
 * @returns {function(config:Object): Promise<MFKDFFactor>} Async function to generate MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.15.0
 * @memberof derive.factors
 */
function stack(factors) {
  return async (params) => {
    const key = await deriveKey(params, factors, false, true);

    return {
      type: "stack",
      data: key.key,
      params: async () => {
        return key.policy;
      },
      output: async () => {
        return key;
      },
    };
  };
}
module.exports.stack = stack;
