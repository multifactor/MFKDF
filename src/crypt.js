const crypto = require('crypto')

/* Encrypts a 32-byte buffer using AES-256-ECB with the given 32-byte key */
// Internal use only
function encrypt (data, key) {
  if (!Buffer.isBuffer(data)) throw new TypeError('data must be a buffer')
  if (data.length !== 32) throw new RangeError('data must be 32 bytes')
  if (!Buffer.isBuffer(key)) throw new TypeError('key must be a buffer')
  if (key.length !== 32) throw new RangeError('key must be 32 bytes')

  const cipher = crypto.createCipheriv('AES-256-ECB', key, '')
  cipher.setAutoPadding(false)
  return Buffer.concat([cipher.update(data), cipher.final()])
}

/* Decrypts a 32-byte buffer using AES-256-ECB with the given 32-byte key */
// Internal use only
function decrypt (data, key) {
  if (!Buffer.isBuffer(data)) throw new TypeError('data must be a buffer')
  if (data.length !== 32) throw new RangeError('data must be 32 bytes')
  if (!Buffer.isBuffer(key)) throw new TypeError('key must be a buffer')
  if (key.length !== 32) throw new RangeError('key must be 32 bytes')

  const decipher = crypto.createDecipheriv('AES-256-ECB', key, '')
  decipher.setAutoPadding(false)
  return Buffer.concat([decipher.update(data), decipher.final()])
}

/* Derives a key using HKDF with the given parameters */
// Internal use only
async function hkdf (hash, key, salt, purpose, size) {
  const importedKey = await crypto.subtle.importKey('raw', key, 'HKDF', false, [
    'deriveBits'
  ])
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: Buffer.from(salt),
      info: Buffer.from(purpose)
    },
    importedKey,
    size * 8
  )
  return Buffer.from(bits)
}

module.exports = { encrypt, decrypt, hkdf }
