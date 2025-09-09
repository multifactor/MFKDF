/* eslint no-unused-expressions: "off" */
const chai = require("chai");
const chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);
chai.should();

const crypt = require("../../src/crypt");
const crypto = require("crypto");
const { suite, test } = require("mocha");

suite("aes", () => {
  test("encrypts and decrypts correctly", async () => {
    const key = crypto.randomBytes(32);
    const data = crypto.randomBytes(32);
    const encrypted = crypt.encrypt(data, key);
    const decrypted = crypt.decrypt(encrypted, key);
    decrypted.equals(data).should.be.true;
  });

  test("decrypting with wrong key fails", async () => {
    const key = crypto.randomBytes(32);
    const wrongKey = crypto.randomBytes(32);
    const data = crypto.randomBytes(32);
    const encrypted = crypt.encrypt(data, key);
    const decrypted = crypt.decrypt(encrypted, wrongKey);
    decrypted.equals(data).should.be.false;
  });

  test("decrypting modified data fails", async () => {
    const key = crypto.randomBytes(32);
    const data = crypto.randomBytes(32);
    const encrypted = crypt.encrypt(data, key);
    // Modify the encrypted data
    encrypted[0] ^= 0xff;
    const decrypted = crypt.decrypt(encrypted, key);
    decrypted.equals(data).should.be.false;
  });

  test("ciphertext length equals plaintext length", async () => {
    const key = crypto.randomBytes(32);
    const data = crypto.randomBytes(32);
    const encrypted = crypt.encrypt(data, key);
    encrypted.length.should.equal(data.length);
  });
});
