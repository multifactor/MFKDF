/**
 * Multi-factor derived key setup
 *
 * @namespace setup
 */
module.exports = {
  ...require('./kdf'),
  ...require('./mfkdf')
}
