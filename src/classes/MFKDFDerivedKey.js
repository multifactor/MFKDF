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
   */
  constructor(policy, key) {
    this.policy = policy;
    this.key = value;
  }
}

module.exports = MFKDFDerivedKey;
