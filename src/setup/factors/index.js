/**
 * Multi-factor key derivation factor setup
 *
 * @namespace setup.factors
 */

module.exports = {
  ...require('./password'),
  ...require('./uuid'),
  ...require('./hotp'),
  ...require('./totp'),
  ...require('./stack'),
  ...require('./hmacsha1'),
  ...require('./question')
}
