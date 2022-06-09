/**
 * Multi-factor key derivation factor derivation
 *
 * @namespace derive.factors
 * @memberof derive
 */

module.exports = {
  ...require('./password'),
  ...require('./uuid'),
  ...require('./hotp'),
  ...require('./totp'),
  ...require('./stack'),
  ...require('./persisted'),
  ...require('./hmacsha1'),
  ...require('./question'),
  ...require('./ooba')
}
