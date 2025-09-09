const crypto = require("crypto");

/* Encrypts a 32-byte buffer using AES-256-ECB with the given 32-byte key */
// Internal use only
function encrypt(data, key) {
  if (!Buffer.isBuffer(data)) throw new TypeError("data must be a buffer");
  if (data.length !== 32) throw new RangeError("data must be 32 bytes");
  if (!Buffer.isBuffer(key)) throw new TypeError("key must be a buffer");
  if (key.length !== 32) throw new RangeError("key must be 32 bytes");

  const cipher = crypto.createCipheriv("AES-256-ECB", key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

/* Decrypts a 32-byte buffer using AES-256-ECB with the given 32-byte key */
// Internal use only
function decrypt(data, key) {
  if (!Buffer.isBuffer(data)) throw new TypeError("data must be a buffer");
  if (data.length !== 32) throw new RangeError("data must be 32 bytes");
  if (!Buffer.isBuffer(key)) throw new TypeError("key must be a buffer");
  if (key.length !== 32) throw new RangeError("key must be 32 bytes");

  const decipher = crypto.createDecipheriv("AES-256-ECB", key, null);
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

module.exports = { encrypt, decrypt };
