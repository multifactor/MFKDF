/**
 * @file Multi-Factor Derived Key Reconstitution Functions
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Operations for reconstituting a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const share = require('../../secrets/share').share
const crypto = require('crypto')
const { decrypt, encrypt, hkdf } = require('../../crypt')
const { extract } = require('../../integrity')

/**
 * Change the threshold of factors needed to derive a multi-factor derived key
 *
 * @example
 * // setup 3-factor multi-factor derived key
 * const setup = await mfkdf.setup.key([
 *  await mfkdf.setup.factors.password('password1', { id: 'password1' }),
 *  await mfkdf.setup.factors.password('password2', { id: 'password2' }),
 *  await mfkdf.setup.factors.password('password3', { id: 'password3' })
 * ])
 *
 * // change threshold to 2/3
 * await setup.setThreshold(2)
 *
 * // derive key with 2 factors
 * const derived = await mfkdf.derive.key(setup.policy, {
 *  password1: mfkdf.derive.factors.password('password1'),
 *  password3: mfkdf.derive.factors.password('password3')
 * })
 *
 * setup.key.toString('hex') // -> 6458…dc3c
 * derived.key.toString('hex') // -> 6458…dc3c
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
 * @example
 * // setup 2-of-3-factor multi-factor derived key
 * const setup = await mfkdf.setup.key([
 *  await mfkdf.setup.factors.password('password1', { id: 'password1' }),
 *  await mfkdf.setup.factors.password('password2', { id: 'password2' }),
 *  await mfkdf.setup.factors.password('password3', { id: 'password3' })
 * ], {threshold: 2})
 *
 * // remove one of the factors
 * await setup.removeFactor('password2')
 *
 * // derive key with remaining 2 factors
 * const derived = await mfkdf.derive.key(setup.policy, {
 *  password1: mfkdf.derive.factors.password('password1'),
 *  password3: mfkdf.derive.factors.password('password3')
 * })
 *
 * setup.key.toString('hex') // -> 6458…dc3c
 * derived.key.toString('hex') // -> 6458…dc3c
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
 * @example
 * // setup 1-of-3-factor multi-factor derived key
 * const setup = await mfkdf.setup.key([
 *  await mfkdf.setup.factors.password('password1', { id: 'password1' }),
 *  await mfkdf.setup.factors.password('password2', { id: 'password2' }),
 *  await mfkdf.setup.factors.password('password3', { id: 'password3' })
 * ], {threshold: 1})
 *
 * // remove two factors
 * await setup.removeFactors(['password1', 'password2'])
 *
 * // derive key with remaining factor
 * const derived = await mfkdf.derive.key(setup.policy, {
 *  password3: mfkdf.derive.factors.password('password3')
 * })
 *
 * setup.key.toString('hex') // -> 6458…dc3c
 * derived.key.toString('hex') // -> 6458…dc3c
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
 * @example
 * // setup 2-of-3-factor multi-factor derived key
 * const setup = await mfkdf.setup.key([
 *  await mfkdf.setup.factors.password('password1', { id: 'password1' }),
 *  await mfkdf.setup.factors.password('password2', { id: 'password2' }),
 *  await mfkdf.setup.factors.password('password3', { id: 'password3' })
 * ], {threshold: 2})
 *
 * // add fourth factor
 * await setup.addFactor(
 *  await mfkdf.setup.factors.password('password4', { id: 'password4' })
 * )
 *
 * // derive key with any 2 factors
 * const derived = await mfkdf.derive.key(setup.policy, {
 *  password2: mfkdf.derive.factors.password('password2'),
 *  password4: mfkdf.derive.factors.password('password4')
 * })
 *
 * setup.key.toString('hex') // -> 6458…dc3c
 * derived.key.toString('hex') // -> 6458…dc3c
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
 * @example
 * // setup 2-of-3-factor multi-factor derived key
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.password('password1', { id: 'password1' }),
 *   await mfkdf.setup.factors.password('password2', { id: 'password2' }),
 *   await mfkdf.setup.factors.password('password3', { id: 'password3' })
 * ], {threshold: 2})
 *
 * // add two more factors
 * await setup.addFactors([
 *   await mfkdf.setup.factors.password('password4', { id: 'password4' }),
 *   await mfkdf.setup.factors.password('password5', { id: 'password5' })
 * ])
 *
 * // derive key with any 2 factors
 * const derived = await mfkdf.derive.key(setup.policy, {
 *   password3: mfkdf.derive.factors.password('password3'),
 *   password5: mfkdf.derive.factors.password('password5')
 * })
 *
 * setup.key.toString('hex') // -> 6458…dc3c
 * derived.key.toString('hex') // -> 6458…dc3c
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
 * @example
 * // setup 3-factor multi-factor derived key
 * const setup = await mfkdf.setup.key([
 *  await mfkdf.setup.factors.password('password1', { id: 'password1' }),
 *  await mfkdf.setup.factors.password('password2', { id: 'password2' }),
 *  await mfkdf.setup.factors.password('password3', { id: 'password3' })
 * ])
 *
 * // change the 2nd factor
 * await setup.recoverFactor(
 *  await mfkdf.setup.factors.password('newPassword2', { id: 'password2' })
 * )
 *
 * // derive key with new factors
 * const derived = await mfkdf.derive.key(setup.policy, {
 *  password1: mfkdf.derive.factors.password('password1'),
 *  password2: mfkdf.derive.factors.password('newPassword2'),
 *  password3: mfkdf.derive.factors.password('password3')
 * })
 *
 * setup.key.toString('hex') // -> 6458…dc3c
 * derived.key.toString('hex') // -> 6458…dc3c
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
 * @example
 * // setup 3-factor multi-factor derived key
 * const setup = await mfkdf.setup.key([
 *  await mfkdf.setup.factors.password('password1', { id: 'password1' }),
 *  await mfkdf.setup.factors.password('password2', { id: 'password2' }),
 *  await mfkdf.setup.factors.password('password3', { id: 'password3' })
 * ])
 *
 * // change 2 factors
 * await setup.recoverFactors([
 *  await mfkdf.setup.factors.password('newPassword2', { id: 'password2' }),
 *  await mfkdf.setup.factors.password('newPassword3', { id: 'password3' })
 * ])
 *
 * // derive key with new factors
 * const derived = await mfkdf.derive.key(setup.policy, {
 *  password1: mfkdf.derive.factors.password('password1'),
 *  password2: mfkdf.derive.factors.password('newPassword2'),
 *  password3: mfkdf.derive.factors.password('newPassword3')
 * })
 *
 * setup.key.toString('hex') // -> 6458…dc3c
 * derived.key.toString('hex') // -> 6458…dc3c
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
 * @example
 * // setup 2-of-3-factor multi-factor derived key
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.password('password1', { id: 'password1' }),
 *   await mfkdf.setup.factors.password('password2', { id: 'password2' }),
 *   await mfkdf.setup.factors.password('password3', { id: 'password3' })
 * ], {threshold: 2})
 *
 * // remove 1 factor and add 1 new factor
 * await setup.reconstitute(
 *   ['password1'], // remove
 *   [ await mfkdf.setup.factors.password('password4', { id: 'password4' }) ] // add
 * )
 *
 * // derive key with new factors
 * const derived = await mfkdf.derive.key(setup.policy, {
 *   password3: mfkdf.derive.factors.password('password3'),
 *   password4: mfkdf.derive.factors.password('password4')
 * })
 *
 * setup.key.toString('hex') // -> 6458…dc3c
 * derived.key.toString('hex') // -> 6458…dc3c
 *
 * @param {Array.<string>} [removeFactors] - Array of IDs of existing factors to remove
 * @param {Array.<MFKDFFactor>} [addFactors] - Array of factors to add or replace
 * @param {number} [threshold] - New threshold for key derivation; same as current by default
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.14.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function reconstitute (
  removeFactors = [],
  addFactors = [],
  threshold = this.policy.threshold
) {
  if (!Array.isArray(removeFactors)) {
    throw new TypeError('removeFactors must be an array')
  }
  if (!Array.isArray(addFactors)) {
    throw new TypeError('addFactors must be an array')
  }
  if (!Number.isInteger(threshold)) {
    throw new TypeError('threshold must be an integer')
  }
  if (threshold <= 0) throw new RangeError('threshold must be positive')

  const factors = {}
  const material = {}
  const outputs = {}
  const data = {}

  // add existing factors
  for (const factor of this.policy.factors.values()) {
    factors[factor.id] = factor
    const pad = Buffer.from(factor.secret, 'base64')
    const secretKey = Buffer.from(
      await hkdf(
        'sha256',
        this.key,
        Buffer.from(factor.salt, 'base64'),
        'mfkdf2:factor:secret:' + factor.id,
        32
      )
    )
    const factorMaterial = decrypt(pad, secretKey)
    material[factor.id] = factorMaterial
  }

  // remove selected factors
  for (const factor of removeFactors) {
    if (typeof factor !== 'string') {
      throw new TypeError('factor must be a string')
    }
    if (typeof factors[factor] !== 'object') {
      throw new RangeError('factor does not exist: ' + factor)
    }
    delete factors[factor]
    delete material[factor]
  }

  // add new factors
  for (const factor of addFactors) {
    // type
    if (typeof factor.type !== 'string') {
      throw new TypeError('factor type must be a string')
    }
    if (factor.type.length === 0) {
      throw new RangeError('factor type must not be empty')
    }

    // id
    if (typeof factor.id !== 'string') {
      throw new TypeError('factor id must be a string')
    }
    if (factor.id.length === 0) {
      throw new RangeError('factor id must not be empty')
    }

    // data
    if (!Buffer.isBuffer(factor.data)) {
      throw new TypeError('factor data must be a buffer')
    }
    if (factor.data.length === 0) {
      throw new RangeError('factor data must not be empty')
    }

    // params
    if (typeof factor.params !== 'function') {
      throw new TypeError('factor params must be a function')
    }

    // output
    if (typeof factor.output !== 'function') {
      throw new TypeError('factor output must be a function')
    }

    const salt = crypto.randomBytes(32)
    const paramsKey = Buffer.from(
      await hkdf(
        'sha256',
        this.key,
        salt,
        'mfkdf2:factor:params:' + factor.id,
        32
      )
    )

    factors[factor.id] = {
      id: factor.id,
      type: factor.type,
      params: await factor.params({ key: paramsKey }),
      salt: salt.toString('base64')
    }
    outputs[factor.id] = await factor.output()
    data[factor.id] = factor.data
    if (Buffer.isBuffer(material[factor.id])) delete material[factor.id]
  }

  // new factor id uniqueness
  const ids = addFactors.map((factor) => factor.id)
  if (new Set(ids).size !== ids.length) {
    throw new RangeError('factor ids must be unique')
  }

  // threshold correctness
  const n = Object.entries(factors).length
  if (!(threshold <= n)) {
    throw new RangeError('threshold cannot be greater than number of factors')
  }

  const shares = share(this.secret, threshold, n)

  const newFactors = []

  for (const [index, factor] of Object.values(factors).entries()) {
    const share = shares[index]

    const stretched = Buffer.isBuffer(material[factor.id])
      ? material[factor.id]
      : Buffer.from(
        await hkdf(
          'sha256',
          data[factor.id],
          Buffer.from(factor.salt, 'base64'),
          'mfkdf2:factor:pad:' + factor.id,
          32
        )
      )
    factor.pad = encrypt(share, stretched).toString('base64')

    const secretKey = Buffer.from(
      await hkdf(
        'sha256',
        this.key,
        Buffer.from(factor.salt, 'base64'),
        'mfkdf2:factor:secret:' + factor.id,
        32
      )
    )
    factor.secret = encrypt(stretched, secretKey).toString('base64')

    newFactors.push(factor)
  }

  this.policy.factors = newFactors
  this.policy.threshold = threshold
  this.outputs = outputs
  this.shares = shares

  if (this.policy.hmac) {
    const integrityKey = await hkdf(
      'sha256',
      this.key,
      Buffer.from(this.policy.salt, 'base64'),
      'mfkdf2:integrity',
      32
    )
    const newPolicyData = await extract(this.policy)
    const newHmac = crypto.createHmac('sha256', integrityKey)
    newHmac.update(newPolicyData)
    this.policy.hmac = newHmac.digest('base64')
  }
}
module.exports.reconstitute = reconstitute
