/**
 * @file MFKDF Policy Logic
 * @copyright Multifactor, Inc. 2022–2025
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
 * // derive key with passwordA and passwordC (or passwordA and passwordB)
 * const derive = await mfkdf.policy.derive(setup.policy, {
 *   passwordA: mfkdf.derive.factors.password('passwordA'),
 *   passwordC: mfkdf.derive.factors.password('passwordC'),
 * })
 *
 * setup.key.toString('hex') // -> e16a…5263
 * derive.key.toString('hex') // -> e16a…5263
 *
 * @param {MFKDFFactor} factor1 - The first factor input to the OR policy
 * @param {MFKDFFactor} factor2 - The second factor input to the OR policy
 * @returns {MFKDFFactor} Factor that can be derived with either factor
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
 * // derive key with passwordA and passwordC (or passwordA and passwordB)
 * const derive = await mfkdf.policy.derive(setup.policy, {
 *   passwordA: mfkdf.derive.factors.password('passwordA'),
 *   passwordC: mfkdf.derive.factors.password('passwordC'),
 * })
 *
 * setup.key.toString('hex') // -> e16a…5263
 * derive.key.toString('hex') // -> e16a…5263
 *
 * @param {MFKDFFactor} factor1 - The first factor input to the AND policy
 * @param {MFKDFFactor} factor2 - The second factor input to the AND policy
 * @returns {MFKDFFactor} Factor that can be derived with both factors
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
 * // setup key that can be derived from passwordA AND passwordB AND passwordC
 * const setup = await mfkdf.policy.setup(
 *   await mfkdf.policy.all([
 *     await mfkdf.setup.factors.password('passwordA', { id: 'passwordA' }),
 *     await mfkdf.setup.factors.password('passwordB', { id: 'passwordB' }),
 *     await mfkdf.setup.factors.password('passwordC', { id: 'passwordC' })
 *   ])
 * )
 *
 * // derive key with passwordA and passwordB and passwordC
 * const derive = await mfkdf.policy.derive(setup.policy, {
 *   passwordA: mfkdf.derive.factors.password('passwordA'),
 *   passwordB: mfkdf.derive.factors.password('passwordB'),
 *   passwordC: mfkdf.derive.factors.password('passwordC'),
 * })
 *
 * setup.key.toString('hex') // -> e16a…5263
 * derive.key.toString('hex') // -> e16a…5263
 *
 * @param {Array.<MFKDFFactor>} factors - The factor inputs to the ALL policy
 * @returns {MFKDFFactor} Factor that can be derived with all factors
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
 * // setup key that can be derived from passwordA OR passwordB OR passwordC
 * const setup = await mfkdf.policy.setup(
 *   await mfkdf.policy.any([
 *     await mfkdf.setup.factors.password('passwordA', { id: 'passwordA' }),
 *     await mfkdf.setup.factors.password('passwordB', { id: 'passwordB' }),
 *     await mfkdf.setup.factors.password('passwordC', { id: 'passwordC' })
 *   ])
 * )
 *
 * // derive key with passwordA (or passwordB or passwordC)
 * const derive = await mfkdf.policy.derive(setup.policy, {
 *   passwordB: mfkdf.derive.factors.password('passwordB')
 * })
 *
 * setup.key.toString('hex') // -> e16a…5263
 * derive.key.toString('hex') // -> e16a…5263
 *
 * @param {Array.<MFKDFFactor>} factors - The factor inputs to the ANY policy
 * @returns {MFKDFFactor} Factor that can be derived with any factor
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
 * // setup key that can be derived from at least 2 of (passwordA, passwordB, passwordC)
 * const setup = await mfkdf.policy.setup(
 *   await mfkdf.policy.any([
 *     await mfkdf.setup.factors.password('passwordA', { id: 'passwordA' }),
 *     await mfkdf.setup.factors.password('passwordB', { id: 'passwordB' }),
 *     await mfkdf.setup.factors.password('passwordC', { id: 'passwordC' })
 *   ])
 * )
 *
 * // derive key with passwordA and passwordB (or passwordA and passwordC, or passwordB and passwordC)
 * const derive = await mfkdf.policy.derive(setup.policy, {
 *   passwordA: mfkdf.derive.factors.password('passwordA'),
 *   passwordB: mfkdf.derive.factors.password('passwordB')
 * })
 *
 * setup.key.toString('hex') // -> e16a…5263
 * derive.key.toString('hex') // -> e16a…5263
 *
 * @param {number} n - The number of factors to be required
 * @param {Array.<MFKDFFactor>} factors - The factor inputs to the atLeast(#) policy
 * @returns {MFKDFFactor} Factor that can be derived with at least n of the given factors
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
