/**
 * @file MFKDF Policy Logic
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Logical operators for MFKDF policy establishment
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const stack = require('../setup/factors/stack').stack
const { v4: uuidv4 } = require('uuid')

/**
 * Create a MFKDF factor based on OR of two MFKDF factors
 *
 * @example
 * const factor = await mfkdf.policy.or( ... );
 *
 * @param {MFKDFFactor} factor1 - the first factor input to the OR policy
 * @param {MFKDFFactor} factor2 - the second factor input to the OR policy
 * @returns {MFKDFFactor} factor that can be derived with either factor
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.16.0
 * @async
 * @memberOf policy
 */
async function or (factor1, factor2) {
  return await atLeast(1, [factor1, factor2])
}
module.exports.or = or

/**
  * Create a MFKDF factor based on AND of two MFKDF factors
  *
  * @example
  * const factor = await mfkdf.policy.and( ... );
  *
  * @param {MFKDFFactor} factor1 - the first factor input to the AND policy
  * @param {MFKDFFactor} factor2 - the second factor input to the AND policy
  * @returns {MFKDFFactor} factor that can be derived with both factors
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.16.0
  * @async
  * @memberOf policy
  */
async function and (factor1, factor2) {
  return await atLeast(2, [factor1, factor2])
}
module.exports.and = and

/**
  * Create a MFKDF factor based on ALL of the provided MFKDF factors
  *
  * @example
  * const factor = await mfkdf.policy.all( ... );
  *
  * @param {Array.<MFKDFFactor>} factors - the factor inputs to the ALL policy
  * @returns {MFKDFFactor} factor that can be derived with all factors
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.16.0
  * @async
  * @memberOf policy
  */
async function all (factors) {
  return await atLeast(factors.length, factors)
}
module.exports.all = all

/**
  * Create a MFKDF factor based on ANY of the provided MFKDF factors
  *
  * @example
  * const factor = await mfkdf.policy.any( ... );
  *
  * @param {Array.<MFKDFFactor>} factors - the factor inputs to the ANY policy
  * @returns {MFKDFFactor} factor that can be derived with any factor
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.16.0
  * @async
  * @memberOf policy
  */
async function any (factors) {
  return await atLeast(1, factors)
}
module.exports.any = any

/**
  * Create a MFKDF factor based on at least some number of the provided MFKDF factors
  *
  * @example
  * const factor = await mfkdf.policy.atLeast( ... );
  *
  * @param {number} n - the number of factors to be requested
  * @param {Array.<MFKDFFactor>} factors - the factor inputs to the atLeast(#) policy
  * @returns {MFKDFFactor} factor that can be derived with at least n of the given factors
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.16.0
  * @async
  * @memberOf policy
  */
async function atLeast (n, factors) {
  const id = uuidv4()
  return await stack(factors, { threshold: n, id })
}
module.exports.atLeast = atLeast
