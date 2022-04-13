(function webpackUniversalModuleDefinition(root, factory) {
	if(typeof exports === 'object' && typeof module === 'object')
		module.exports = factory();
	else if(typeof define === 'function' && define.amd)
		define([], factory);
	else if(typeof exports === 'object')
		exports["mfkdf"] = factory();
	else
		root["mfkdf"] = factory();
})(self, function() {
return /******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 930:
/***/ ((module) => {

/**
 * @file Safe MFKDF Defaults
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Secure default configuration for multi-factor key derivation function (MFKDF) and MFKDF factor constructions
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

module.exports.kdf = {
  kdf: 'argon2id', // pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id (default)
  pbkdf2rounds: 310000, // owasp recommendation
  pbkdf2digest: 'sha256', // sha256 and sha512 are common; see crypto.getHashes() for options
  bcryptrounds: 10, // owasp recommendation
  scryptcost: 16384, // 2**14; scrypt paper recommendation
  scryptblocksize: 8, // recommended value
  scryptparallelism: 1, // disable parallelism
  argon2time: 2, // owasp recommendation
  argon2mem: 24576, // 24 MiB; slightly more than owasp recommendation
  argon2parallelism: 1 // disable parallelism
}


/***/ }),

/***/ 138:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

module.exports = {
  setup: __webpack_require__(275)
}


/***/ }),

/***/ 275:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

/**
 * Multi-factor derived key setup
 *
 * @namespace setup
 */
module.exports = {
  ...__webpack_require__(336)
}


/***/ }),

/***/ 336:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

/**
 * @file Key Derivation Function (KDF) Setup
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Validate and setup a KDF configuration for a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const defaults = __webpack_require__(930)

/**
  * Validate and setup a KDF configuration for a multi-factor derived key
  *
  * @example
  * const config = await mfkdf.setup.kdf({
  *   kdf: 'pbkdf2',
  *   pbkdf2rounds: 100000,
  *   pbkdf2digest: 'sha256'
  * });
  *
  * @param {Object} [options] - KDF configuration options
  * @param {string} [options.kdf=argon2id] - KDF algorithm to use; one of pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id
  * @param {number} [options.pbkdf2rounds=310000] - number of rounds to use if using pbkdf2
  * @param {string} [options.pbkdf2digest=sha256] - hash function to use if using pbkdf2; one of sha1, sha256, sha384, or sha512
  * @param {number} [options.bcryptrounds=10] - number of rounds to use if using bcrypt
  * @param {number} [options.scryptcost=16384] - iterations count (N) to use if using scrypt
  * @param {number} [options.scryptblocksize=8] - block size (r) to use if using scrypt
  * @param {number} [options.scryptparallelism=1] - parallelism factor (p) to use if using scrypt
  * @param {number} [options.argon2time=2] - iterations to use if using argon2
  * @param {number} [options.argon2mem=24576] - memory to use if using argon2
  * @param {number} [options.argon2parallelism=24576] - parallelism to use if using argon2
  * @returns A KDF configuration as a JSON object.
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.7.0
  * @memberOf setup
  */
function kdf (options) {
  options = Object.assign(Object.assign({}, defaults.kdf), options)
  if (typeof options.kdf !== 'string') throw new TypeError('kdf must be a string')
  const config = {
    type: options.kdf,
    params: {}
  }
  if (options.kdf === 'pbkdf2') {
    // pbkdf2 rounds
    if (!(Number.isInteger(options.pbkdf2rounds))) throw new TypeError('pbkdf2rounds must be an integer')
    if (!(options.pbkdf2rounds > 0)) throw new RangeError('pbkdf2rounds must be positive')
    config.params.rounds = options.pbkdf2rounds

    // pbkdf2 digest
    if (typeof options.pbkdf2digest !== 'string') throw new TypeError('pbkdf2digest must be a string')
    if (!['sha1', 'sha256', 'sha384', 'sha512'].includes(options.pbkdf2digest)) throw new RangeError('pbkdf2digest must be one of sha1, sha256, sha384, or sha512')
    config.params.digest = options.pbkdf2digest
  } else if (options.kdf === 'bcrypt') {
    // bcrypt rounds
    if (!(Number.isInteger(options.bcryptrounds))) throw new TypeError('bcryptrounds must be an integer')
    if (!(options.bcryptrounds > 0)) throw new RangeError('bcryptrounds must be positive')
    config.params.rounds = options.bcryptrounds
  } else if (options.kdf === 'scrypt') {
    // scrypt rounds
    if (!(Number.isInteger(options.scryptcost))) throw new TypeError('scryptcost must be a positive integer')
    if (!(options.scryptcost > 0)) throw new RangeError('scryptcost must be positive')
    config.params.rounds = options.scryptcost

    // scrypt block size
    if (!(Number.isInteger(options.scryptblocksize))) throw new TypeError('scryptblocksize must be an integer')
    if (!(options.scryptblocksize > 0)) throw new RangeError('scryptblocksize must be positive')
    config.params.blocksize = options.scryptblocksize

    // scrypt parallelism
    if (!(Number.isInteger(options.scryptparallelism))) throw new TypeError('scryptparallelism must be an integer')
    if (!(options.scryptparallelism > 0)) throw new RangeError('scryptparallelism must be positive')
    config.params.parallelism = options.scryptparallelism
  } else if (options.kdf === 'argon2i' || options.kdf === 'argon2d' || options.kdf === 'argon2id') {
    // argon2 rounds
    if (!(Number.isInteger(options.argon2time))) throw new TypeError('argon2time must be an integer')
    if (!(options.argon2time > 0)) throw new RangeError('argon2time must be positive')
    config.params.rounds = options.argon2time

    // argon2 memory
    if (!(Number.isInteger(options.argon2mem))) throw new TypeError('argon2mem must be an integer')
    if (!(options.argon2mem > 0)) throw new RangeError('argon2mem must be positive')
    config.params.memory = options.argon2mem

    // argon2 parallelism
    if (!(Number.isInteger(options.argon2parallelism))) throw new TypeError('argon2parallelism must be an integer')
    if (!(options.argon2parallelism > 0)) throw new RangeError('argon2parallelism must be positive')
    config.params.parallelism = options.argon2parallelism
  } else {
    throw new RangeError('kdf must be one of pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id')
  }
  return config
}
module.exports.kdf = kdf


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module is referenced by other modules so it can't be inlined
/******/ 	var __webpack_exports__ = __webpack_require__(138);
/******/ 	
/******/ 	return __webpack_exports__;
/******/ })()
;
});