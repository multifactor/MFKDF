/**
 * Multi-factor key derivation factor setup
 *
 * @namespace setup.factors
 */

/**
  * @typedef MFKDFFactor
  * @type {object}
  * @property {string} type - Type of factor.
  * @property {Buffer} data - Key material for this factor.
  * @property {function} params - Asynchronous function to fetch parameters.
  */

module.exports = {
  ...require('./password')
}
