(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
module.exports = {
  ...require('./mfkdf')
}

},{"./mfkdf":2}],2:[function(require,module,exports){
/**
 * @file Multi-Factor Key Derivation Function (MFKDF)
 * @copyright Multifactor 2021 All Rights Reserved
 *
 * @description
 * JavaScript Implementation of a Multi-Factor Key Derivation Function (MFKDF)
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

 /**
  * Derive a key. Placeholder.
  *
  * @example
  * mfkdf.derive();
  *
  * @param {Array} factors - The factors.
  * @returns A derived key.
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 1.0.0
  */
module.exports.derive = function derive (factors) {
  return true
}

},{}]},{},[1]);
