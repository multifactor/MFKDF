/**
 * @file Safe MFKDF Defaults
 * @copyright Multifactor 2021 All Rights Reserved
 *
 * @description
 * Secure default configuration for MFKDF
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

module.exports.kdf = {
  size: 32, // key size (bytes); outputs 256-bit key by default
  kdf: 'argon2', // pbkdf2, bcrypt, scrypt, or argon2 (default)
  pbkdf2rounds: 310000, // owasp recommendation
  pbkdf2digest: 'sha256', // sha256 and sha512 are common; see crypto.getHashes() for options
  bcryptrounds: 10, // owasp recommendation
  scryptcost: 16384, // 2**14; scrypt paper recommendation
  scryptblocksize: 8, // recommended value
  scryptparallelism: 1 // disable parallelism
}
