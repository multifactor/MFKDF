/**
 * Secrets management
 *
 * @namespace secrets
 * @deprecated
 */
module.exports = {
  ...require('./share'),
  ...require('./combine'),
  ...require('./recover')
}
