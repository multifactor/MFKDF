/**
 * Multi-factor key derivation factor derivation
 *
 * @namespace derive.factors
 */

module.exports = {
  ...require('./password'),
  ...require('./uuid'),
  ...require('./hotp'),
  ...require('./totp'),
  ...require('./stack')
}
