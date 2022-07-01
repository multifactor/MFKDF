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
 * Class representing a multi-factor derived key
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.8.0
 */
class MFKDFDerivedKey {
  /**
   * Create a MFKDFDerivedKey object
   *
   * @param {Object} policy - The policy for deriving this key
   * @param {Buffer} key - The value of this derived key
   * @param {Buffer} secret - The secret (pre-KDF) value of this derived key
   * @param {Array.<Buffer>} shares - The shares corresponding to the factors of this key
   * @param {Array.<Object>} outputs - The outputs corresponding to the factors of this key
   */
  constructor (policy, key, secret, shares, outputs) {
    this.policy = policy
    this.key = key
    this.secret = secret
    this.shares = shares
    this.outputs = outputs
    this.subkeys = {}
  }
}

// Crypto Functions
const crypto = require('./crypto')
MFKDFDerivedKey.prototype.getSubkey = crypto.getSubkey
MFKDFDerivedKey.prototype.getSymmetricKey = crypto.getSymmetricKey
MFKDFDerivedKey.prototype.getAsymmetricKeyPair = crypto.getAsymmetricKeyPair
MFKDFDerivedKey.prototype.sign = crypto.sign
MFKDFDerivedKey.prototype.verify = crypto.verify
MFKDFDerivedKey.prototype.encrypt = crypto.encrypt
MFKDFDerivedKey.prototype.decrypt = crypto.decrypt

// Reconstitution Functions
const reconstitution = require('./reconstitution')
MFKDFDerivedKey.prototype.setThreshold = reconstitution.setThreshold
MFKDFDerivedKey.prototype.removeFactor = reconstitution.removeFactor
MFKDFDerivedKey.prototype.removeFactors = reconstitution.removeFactors
MFKDFDerivedKey.prototype.addFactor = reconstitution.addFactor
MFKDFDerivedKey.prototype.addFactors = reconstitution.addFactors
MFKDFDerivedKey.prototype.recoverFactor = reconstitution.recoverFactor
MFKDFDerivedKey.prototype.recoverFactors = reconstitution.recoverFactors
MFKDFDerivedKey.prototype.reconstitute = reconstitution.reconstitute

// Authentication Functions
const auth = require('./auth')
MFKDFDerivedKey.prototype.ISO97982PassUnilateralAuthSymmetric = auth.ISO97982PassUnilateralAuthSymmetric
MFKDFDerivedKey.prototype.ISO97982PassUnilateralAuthAsymmetric = auth.ISO97982PassUnilateralAuthAsymmetric
MFKDFDerivedKey.prototype.ISO97982PassUnilateralAuthCCF = auth.ISO97982PassUnilateralAuthCCF
MFKDFDerivedKey.prototype.ISO97981PassUnilateralAuthSymmetric = auth.ISO97981PassUnilateralAuthSymmetric
MFKDFDerivedKey.prototype.ISO97981PassUnilateralAuthAsymmetric = auth.ISO97981PassUnilateralAuthAsymmetric
MFKDFDerivedKey.prototype.ISO97981PassUnilateralAuthCCF = auth.ISO97981PassUnilateralAuthCCF
MFKDFDerivedKey.prototype.ISO9798SymmetricKey = auth.ISO9798SymmetricKey
MFKDFDerivedKey.prototype.ISO9798AsymmetricKey = auth.ISO9798AsymmetricKey
MFKDFDerivedKey.prototype.ISO9798CCFKey = auth.ISO9798CCFKey

// Persistence Functions
const persistence = require('./persistence')
MFKDFDerivedKey.prototype.persistFactor = persistence.persistFactor

// Enveloping Functions
const envelope = require('./envelope')
MFKDFDerivedKey.prototype.addEnvelopedSecret = envelope.addEnvelopedSecret
MFKDFDerivedKey.prototype.removeEnvelopedSecret = envelope.removeEnvelopedSecret
MFKDFDerivedKey.prototype.addEnvelopedKey = envelope.addEnvelopedKey
MFKDFDerivedKey.prototype.getEnvelopedSecret = envelope.getEnvelopedSecret
MFKDFDerivedKey.prototype.getEnvelopedKey = envelope.getEnvelopedKey
MFKDFDerivedKey.prototype.hasEnvelopedSecret = envelope.hasEnvelopedSecret

module.exports = MFKDFDerivedKey
