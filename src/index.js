/**
 * @typedef MFKDFFactor
 * @type {object}
 * @property {string} type - Type of factor
 * @property {string} [id] - Unique identifier of this factor
 * @property {Buffer} data - Key material for this factor
 * @property {function} params - Asynchronous function to fetch parameters
 * @property {number} [entropy] - Actual bits of entropy this factor provides
 * @property {function} [output] - Asynchronous function to fetch output
 */

export * as setup from './setup'
export * as derive from './derive'
export * as secrets from './secrets'
export * as policy from './policy'
export * as stage from './stage'
