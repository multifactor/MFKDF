[![MFKDF](https://raw.githubusercontent.com/multifactor/MFKDF/master/site/logo.png "MFKDF")](https://mfkdf.com/ "MFKDF")

Multi-Factor Key Derivation Function

[![GitHub issues](https://img.shields.io/github/issues/multifactor/MFKDF)](https://github.com/multifactor/MFKDF/issues)
[![GitHub tag](https://img.shields.io/github/tag/multifactor/MFKDF.svg)](https://github.com/multifactor/MFKDF/tags)
[![GitHub release](https://img.shields.io/github/release/multifactor/MFKDF.svg)](https://github.com/multifactor/MFKDF/releases)
[![NPM release](https://img.shields.io/npm/v/mfkdf.svg)](https://www.npmjs.com/package/mfkdf)

[Site](https://mfkdf.com/) |
[Docs](https://mfkdf.com/docs/) |
[Demo](https://mfkdf.com/demo/) |
[Contributing](https://github.com/multifactor/MFKDF/blob/master/CONTRIBUTING.md) |
[Roadmap](https://github.com/multifactor/MFKDF/blob/master/ROADMAP.md) |
[Security](https://github.com/multifactor/MFKDF/blob/master/SECURITY.md) |
[Multifactor](https://github.com/multifactor) |
[Author](https://github.com/VCNinc)

The Multi-Factor Key Derivation Function (MFKDF) is a function that takes multiple inputs and outputs a string of bytes that can be used as a cryptographic key. It serves the same purpose as a pasword-based key derivation function (PBKDF), but is stronger than password-based key derivation due to its support for multiple authentication factors. MFKDF also supports account recovery via K-of-N (secret-sharing style) key derivation.

## Download
### GitHub
[Download Latest Release](https://github.com/multifactor/MFKDF/releases)

## Installation
### In a browser:
Get the latest tag with SRI from [jsDelivr](https://www.jsdelivr.com/package/npm/mfkdf) (recommended), or include the latest version automatically like so:

	<script src="https://cdn.jsdelivr.net/gh/multifactor/mfkdf/mfkdf.min.js"></script>

### Using npm:
	npm install mfkdf

### In Node.js:
	const mfkdf = require('mfkdf');

## Usage
### n-of-n MFKDF
MFKDF allows a key to be derived from several factors of input (eg. multiple passwords).

```
// setup MFKDF where 3/3 passwords are required
const { key, config } = await mfkdf.setup({
	password1: await mfkdf.factors.password('password1'),
	password2: await mfkdf.factors.password('password2'),
	password3: await mfkdf.factors.password('password3')
}, 3)

// derive key using 3/3 passwords
const key2 = await mfkdf.derive({
	password1: await mfkdf.factors.password('password1'),
	password2: await mfkdf.factors.password('password2'),
	password3: await mfkdf.factors.password('password3')
}, config)
console.log(key.toString('hex') === key2.toString('hex')) // true

// incorrect password will yield incorrect key
const key2 = await mfkdf.derive({
	password1: await mfkdf.factors.password('password1'),
	password2: await mfkdf.factors.password('password2'),
	password3: await mfkdf.factors.password('password4')
}, config)
console.log(key.toString('hex') === key2.toString('hex')) // false
```

### k-of-n MFKDF
MFKDF can be configured to use k-of-n secret sharing style derivation (eg. any 2 of 3 passwords are sufficient).

```
// setup MFKDF where 2/3 passwords are required
const { key, config } = await mfkdf.setup({
	password1: await mfkdf.factors.password('password1'),
	password2: await mfkdf.factors.password('password2'),
	password3: await mfkdf.factors.password('password3')
}, 2)

// derive key using 2/3 passwords
const key2 = await mfkdf.derive({
	password1: await mfkdf.factors.password('password1'),
	password2: await mfkdf.factors.password('password2')
}, config)
console.log(key.toString('hex') === key2.toString('hex')) // true

// incorrect password will yield incorrect key
const key2 = await mfkdf.derive({
	password1: await mfkdf.factors.password('password1'),
	password2: await mfkdf.factors.password('password4')
}, config)
console.log(key.toString('hex') === key2.toString('hex')) // false
```

### KDF
This library also supports a number of traditional password-based KDFs (pbkdf2, bcrypt, scrypt, argon2i, argon2d, and argon2id) which can be consumed directly like so:

```
// derive 256b key using pbkdf2-sha256 with 100,000 rounds
const mfkdf = require('mfkdf');
const key = await mfkdf.kdf('password', 'salt', {
  kdf: 'pbkdf2',
  size: 32,
  pbkdf2rounds: 100000,
  pbkdf2digest: 'sha256'
});
```
