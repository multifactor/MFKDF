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
  kdf: 'argon2', // pbkdf2, scrypt, bcrypt, or argon2 (default)
  salt: '', // usually randomized by setup()
  pbkdf2rounds: 250000, // takes about 100ms
  pbkdf2digest: 'sha256' // sha256 and sha512 are common; see crypto.getHashes()
}
