/**
 * @file Stage
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Pre-compute MFKDF factors for benchmarking or performance
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

/**
 * Pre-compute an MFKDF factor setup process.
 * Useful for benchmarking or parallelization where supported.
 *
 * @param {Promise<MFKDFFactor>} factor - An async MFKDF factor setup function promise
 * @param {Buffer} [key] - MFKDF output key, needed to pre-compute factor params
 * @returns {MFKDFFactor} An MFKDF factor whose outputs have been pre-computed
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 1.4.0
 * @async
 * @memberOf stage
 */
async function setup (factor, key) {
  const result = await factor

  if (key) {
    const params = await result.params({ key })
    result.params = Promise.resolve(params)

    const output = await result.output()
    result.output = Promise.resolve(output)
  }

  return result
}

/**
 * Pre-compute an MFKDF factor derivation process.
 * Useful for benchmarking or parallelization where supported.
 *
 * @param {function(config:Object): Promise<MFKDFFactor>} factor - An async MFKDF factor derivation function
 * @param {Object} params - Factor parameters
 * @param {Buffer} [key] - MFKDF output key, needed to pre-compute factor params
 * @returns {function(config:Object): Promise<MFKDFFactor>} An async MFKDF factor derivation function whose outputs have been pre-computed
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 1.4.0
 * @async
 * @memberOf stage
 */
async function derive (factor, params, key) {
  const result = await factor(params)

  if (key) {
    const params = await result.params({ key })
    result.params = Promise.resolve(params)

    const output = await result.output()
    result.output = Promise.resolve(output)
  }

  return () => Promise.resolve(result)
}

module.exports.factor = { setup, derive }
