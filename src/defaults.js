/**
 * @file Safe MFKDF Defaults
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Secure default configuration for multi-factor key derivation function (MFKDF) and MFKDF factor constructions
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
export const password = {
  id: 'password'
}

export const uuid = {
  id: 'uuid'
}

export const question = {
  id: 'question'
}

export const hotp = {
  id: 'hotp',
  hash: 'sha1', // required for Google Authenticator compatibility
  digits: 6, // most common choice
  issuer: 'MFKDF',
  label: 'mfkdf.com'
}

export const totp = {
  id: 'totp',
  hash: 'sha1', // required for Google Authenticator compatibility
  digits: 6, // required for Google Authenticator compatibility
  step: 30, // required for Google Authenticator compatibility
  window: 87600, // max window between logins, 1 month by default
  issuer: 'MFKDF',
  label: 'mfkdf.com'
}

export const ooba = {
  id: 'ooba',
  length: 6
}

export const stack = {
  id: 'stack'
}

export const hmacsha1 = {
  id: 'hmacsha1'
}
