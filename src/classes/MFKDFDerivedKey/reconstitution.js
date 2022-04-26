/**
 * @file Multi-Factor Derived Key Reconstitution Functions
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Operations for reconstituting a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const { hkdf } = require('@panva/hkdf')
const xor = require('buffer-xor')
const share = require('../../secrets/share').share

/**
  * Change the threshold of factors needed to derive a multi-factor derived key
  *
  * @param {number} threshold - New threshold for key derivation
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.14.0
  * @memberOf MFKDFDerivedKey
  * @async
  */
async function setThreshold (threshold) {
  await this.reconstitute([], [], threshold)
}
module.exports.setThreshold = setThreshold

/**
  * Remove a factor used to derive a multi-factor derived key
  *
  * @param {string} id - ID of existing factor to remove
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.14.0
  * @memberOf MFKDFDerivedKey
  * @async
  */
async function removeFactor (id) {
  await this.reconstitute([id])
}
module.exports.removeFactor = removeFactor

/**
  * Remove factors used to derive a multi-factor derived key
  *
  * @param {Array.<string>} ids - Array of IDs of existing factors to remove
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.14.0
  * @memberOf MFKDFDerivedKey
  * @async
  */
async function removeFactors (ids) {
  await this.reconstitute(ids)
}
module.exports.removeFactors = removeFactors

/**
  * Add a factor used to derive a multi-factor derived key
  *
  * @param {MFKDFFactor} factor - Factor to add
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.14.0
  * @memberOf MFKDFDerivedKey
  * @async
  */
async function addFactor (factor) {
  await this.reconstitute([], [factor])
}
module.exports.addFactor = addFactor

/**
  * Add new factors to derive a multi-factor derived key
  *
  * @param {Array.<MFKDFFactor>} factors - Array of factors to add
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.14.0
  * @memberOf MFKDFDerivedKey
  * @async
  */
async function addFactors (factors) {
  await this.reconstitute([], factors)
}
module.exports.addFactors = addFactors

/**
  * Update a factor used to derive a multi-factor derived key
  *
  * @param {MFKDFFactor} factor - Factor to replace
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.14.0
  * @memberOf MFKDFDerivedKey
  * @async
  */
async function recoverFactor (factor) {
  await this.reconstitute([], [factor])
}
module.exports.recoverFactor = recoverFactor

/**
  * Update the factors used to derive a multi-factor derived key
  *
  * @param {Array.<MFKDFFactor>} factors - Array of factors to replace
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.14.0
  * @memberOf MFKDFDerivedKey
  * @async
  */
async function recoverFactors (factors) {
  await this.reconstitute([], factors)
}
module.exports.recoverFactors = recoverFactors

/**
  * Reconstitute the factors used to derive a multi-factor derived key
  *
  * @param {Array.<string>} [removeFactors] - Array of IDs of existing factors to remove
  * @param {Array.<MFKDFFactor>} [addFactors] - Array of factors to add or replace
  * @param {number} [threshold] - New threshold for key derivation; same as current by default
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.14.0
  * @memberOf MFKDFDerivedKey
  * @async
  */
async function reconstitute (removeFactors = [], addFactors = [], threshold = this.policy.threshold) {
  if (!Array.isArray(removeFactors)) throw new TypeError('removeFactors must be an array')
  if (!Array.isArray(addFactors)) throw new TypeError('addFactors must be an array')
  if (!Number.isInteger(threshold)) throw new TypeError('threshold must be an integer')
  if (threshold <= 0) throw new RangeError('threshold must be positive')

  const factors = {}
  const material = {}
  const outputs = {}
  const data = {}

  // add existing factors
  for (const [index, factor] of this.policy.factors.entries()) {
    factors[factor.id] = factor
    const pad = Buffer.from(factor.pad, 'base64')
    const share = this.shares[index]
    let factorMaterial = xor(pad, share)
    if (Buffer.byteLength(factorMaterial) > this.policy.size) factorMaterial = factorMaterial.subarray(Buffer.byteLength(factorMaterial) - this.policy.size)
    material[factor.id] = factorMaterial
  }

  // remove selected factors
  for (const factor of removeFactors) {
    if (typeof factor !== 'string') throw new TypeError('factor must be a string')
    if (typeof factors[factor] !== 'object') throw new RangeError('factor does not exist: ' + factor)
    delete factors[factor]
    delete material[factor]
  }

  // add new factors
  for (const factor of addFactors) {
    // type
    if (typeof factor.type !== 'string') throw new TypeError('factor type must be a string')
    if (factor.type.length === 0) throw new RangeError('factor type must not be empty')

    // id
    if (typeof factor.id !== 'string') throw new TypeError('factor id must be a string')
    if (factor.id.length === 0) throw new RangeError('factor id must not be empty')

    // data
    if (!Buffer.isBuffer(factor.data)) throw new TypeError('factor data must be a buffer')
    if (factor.data.length === 0) throw new RangeError('factor data must not be empty')

    // params
    if (typeof factor.params !== 'function') throw new TypeError('factor params must be a function')

    // output
    if (typeof factor.output !== 'function') throw new TypeError('factor output must be a function')

    factors[factor.id] = {
      id: factor.id,
      type: factor.type,
      params: await factor.params({ key: this.key })
    }
    outputs[factor.id] = await factor.output()
    data[factor.id] = factor.data
    if (Buffer.isBuffer(material[factor.id])) delete material[factor.id]
  }

  // new factor id uniqueness
  const ids = addFactors.map(factor => factor.id)
  if ((new Set(ids)).size !== ids.length) throw new RangeError('factor ids must be unique')

  // threshold correctness
  const n = Object.entries(factors).length
  if (!(threshold <= n)) throw new RangeError('threshold cannot be greater than number of factors')

  const shares = share(this.secret, threshold, n)

  const newFactors = []

  for (const [index, factor] of Object.values(factors).entries()) {
    const share = shares[index]
    let stretched = Buffer.isBuffer(material[factor.id])
      ? material[factor.id]
      : Buffer.from(await hkdf('sha512', data[factor.id], '', '', this.policy.size))

    if (Buffer.byteLength(share) > this.policy.size) stretched = Buffer.concat([Buffer.alloc(Buffer.byteLength(share) - this.policy.size), stretched])

    factor.pad = xor(share, stretched).toString('base64')
    newFactors.push(factor)
  }

  this.policy.factors = newFactors
  this.policy.threshold = threshold
  this.outputs = outputs
  this.shares = shares
}
module.exports.reconstitute = reconstitute
