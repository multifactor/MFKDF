/**
 * Multi-factor key derivation factor setup
 *
 * @namespace setup.factors
 */

module.exports = {
  ...require('./password'),
  ...require('./uuid')
}
