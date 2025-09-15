/**
 * @file Multi-Factor Derived Key Reconstitution Functions
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Operations for strengthening a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const { encrypt } = require("../../crypt");
const { argon2id } = require("hash-wasm");

/**
 * Update the time and/or memory cost of an existing multi-factor derived key.
 * (This can also be used to 'weaken' a key if necessary, but that is not recommended.)
 *
 * @example
 * const setup = await mfkdf.setup.key(
 *   [
 *     await mfkdf.setup.factors.password('password1', {
 *       id: 'password1'
 *     })
 *   ],
 *   { time: 3, memory: 16384 }
 * )
 *
 * setup.policy.time.should.equal(3)
 * setup.policy.memory.should.equal(16384)
 *
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   password1: mfkdf.derive.factors.password('password1')
 * })
 *
 * derive.policy.time.should.equal(3)
 * derive.policy.memory.should.equal(16384)
 *
 * derive.key.toString('hex').should.equal(setup.key.toString('hex'))
 *
 * @param {number} [time] - Additional rounds of argon2 time cost to add; 0 by default
 * @param {number} [memory] - Additional argon2 memory cost to add (in KiB); 0 by default
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 2.0.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function strengthen(time = 0, memory = 0) {
  if (typeof time !== "number" || time < 0 || !Number.isInteger(time)) {
    throw new TypeError("time must be a non-negative integer");
  }
  if (typeof memory !== "number" || memory < 0 || !Number.isInteger(memory)) {
    throw new TypeError("memory must be a non-negative integer");
  }

  this.policy.time = time;
  this.policy.memory = memory;

  const kek = Buffer.from(
    await argon2id({
      password: this.secret,
      salt: Buffer.from(this.policy.salt, "base64"),
      hashLength: 32,
      parallelism: 1,
      iterations: 2 + Math.max(0, time),
      memorySize: 19456 + Math.max(0, memory),
      outputType: "binary",
    })
  );

  this.policy.key = encrypt(this.key, kek).toString("base64");
}
module.exports.strengthen = strengthen;
