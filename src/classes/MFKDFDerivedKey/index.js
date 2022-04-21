/**
 * @file Multi-Factor Derived Key Class
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Class representing a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

/**
 * Class representing a multi-factor derived key.
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.8.0
 */
class MFKDFDerivedKey {
  /**
   * Create a MFKDFDerivedKey object.
   * @param {Object} policy - The policy for deriving this key.
   * @param {Buffer} key - The value of this derived key.
   * @param {Buffer} secret - The secret (pre-KDF) value of this derived key.
   * @param {Array.<Buffer>} shares - The shares corresponding to the factors of this key.
   * @param {Array.<Object>} outputs - The outputs corresponding to the factors of this key.
   */
  constructor (policy, key, secret, shares, outputs) {
    this.policy = policy
    this.key = key
    this.secret = secret
    this.shares = shares
    this.outputs = outputs
  }
}

const crypto = require('./crypto')
MFKDFDerivedKey.prototype.getSubkey = crypto.getSubkey
MFKDFDerivedKey.prototype.getSymmetricKey = crypto.getSymmetricKey
MFKDFDerivedKey.prototype.getAsymmetricKeyPair = crypto.getAsymmetricKeyPair
MFKDFDerivedKey.prototype.sign = crypto.sign
MFKDFDerivedKey.prototype.verify = crypto.verify
MFKDFDerivedKey.prototype.encrypt = crypto.encrypt
MFKDFDerivedKey.prototype.decrypt = crypto.decrypt

const reconstitution = require('./reconstitution')
MFKDFDerivedKey.prototype.setThreshold = reconstitution.setThreshold
MFKDFDerivedKey.prototype.removeFactor = reconstitution.removeFactor
MFKDFDerivedKey.prototype.removeFactors = reconstitution.removeFactors
MFKDFDerivedKey.prototype.addFactor = reconstitution.addFactor
MFKDFDerivedKey.prototype.addFactors = reconstitution.addFactors
MFKDFDerivedKey.prototype.recoverFactor = reconstitution.recoverFactor
MFKDFDerivedKey.prototype.recoverFactors = reconstitution.recoverFactors
MFKDFDerivedKey.prototype.reconstitute = reconstitution.reconstitute

module.exports = MFKDFDerivedKey