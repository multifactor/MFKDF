/**
 * @typedef MFKDFFactor
 * @type {object}
 * @property {string} type - Type of factor.
 * @property {string} id - Unique identifier of this factor.
 * @property {Buffer} data - Key material for this factor.
 * @property {function} params - Asynchronous function to fetch parameters.
 */

module.exports = {
  setup: require('./setup'),
  secrets: require('./secrets'),
  ...require('./kdf')
}
