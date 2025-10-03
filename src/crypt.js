const crypto = require('crypto')

/* Encrypts a 32-byte buffer using AES-256-ECB with the given 32-byte key */
// Internal use only
export function getWebCrypto() {
  const globalWebCrypto =
    typeof globalThis !== 'undefined' &&
    globalThis.crypto &&
    globalThis.crypto.subtle
  // Fallback for Node 16, which does not expose WebCrypto as a global
  /* istanbul ignore next */
  const webCrypto = globalWebCrypto || crypto.webcrypto.subtle
  return webCrypto
}

/* Encrypts a 32-byte buffer using AES-256-ECB with the given 32-byte key */
// Internal use only
export function encrypt(data, key) {
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
export function decrypt(data, key) {
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
export async function hkdf(hash, key, salt, purpose, size) {
  const webCrypto = getWebCrypto()

  const importedKey = await webCrypto.importKey('raw', key, 'HKDF', false, [
    'deriveBits'
  ])
  const bits = await webCrypto.deriveBits(
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

/* Get a cryptographically secure random integer in range */
/* Inclusive of min, exclusive of max */
// Internal use only
export async function random(min, max) {
  // Calculate the range size
  const range = max - min

  // Generate random bytes until we get a value in our desired range
  while (true) {
    // Generate random bytes
    const randomArray = new Uint32Array(1)
    globalThis.crypto.getRandomValues(randomArray)
    const randomValue = randomArray[0]

    // Calculate the number of complete sets of 'range' in our random value space
    const sets = Math.floor(2 ** 32 / range)

    // If the value is within our valid range, return it
    /* istanbul ignore next */
    if (randomValue < sets * range) {
      return min + (randomValue % range)
    }
    // Otherwise, try again to avoid bias
  }
}

