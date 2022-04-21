/**
 * Multi-factor key derivation policy
 *
 * @namespace policy
 */
module.exports = {
  ...require('./setup'),
  ...require('./derive'),
  ...require('./evaluate'),
  ...require('./logic'),
  ...require('./validate')
}
