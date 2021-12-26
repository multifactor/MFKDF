[![Modular Core](https://raw.githubusercontent.com/multifactor/MFKDF/master/site/logo.png "MFKDF")](https://mfkdf.com/ "MFKDF")

Multi-Factor Key Derivation Function

[![GitHub issues](https://img.shields.io/github/issues/multifactor/MFKDF)](https://github.com/multifactor/MFKDF/issues)
[![GitHub tag](https://img.shields.io/github/tag/multifactor/MFKDF.svg)](https://github.com/multifactor/MFKDF/tags)
[![GitHub release](https://img.shields.io/github/release/multifactor/MFKDF.svg)](https://github.com/multifactor/MFKDF/releases)

[Site](https://mfkdf.com/) |
[Docs](https://mfkdf.com/docs/) |
[Contributing](https://github.com/multifactor/MFKDF/blob/master/CONTRIBUTING.md) |
[Security](https://github.com/multifactor/MFKDF/blob/master/SECURITY.md) |
[Multifactor](https://github.com/multifactor) |
[Author](https://github.com/VCNinc)

The Multi-Factor Key Derivation Function (MFKDF) is a function that takes multiple inputs and outputs a string of bytes that can be used as a cryptographic key. It serves the same purpose as a pasword-based key derivation function (PBKDF), but is stronger than password-based key derivation due to its support for multiple authentication factors. MFKDF also supports account recovery via K-of-N (secret-sharing style) key derivation.

## Download
### GitHub
[Download Latest Release](https://github.com/multifactor/MFKDF/releases)

## Installation
### In a browser:
	<script src="https://cdn.jsdelivr.net/gh/multifactor/mfkdf/mfkdf.min.js></script>

### Using npm:
	npm install mfkdf

### In Node.js:
	const mfkdf = require('mfkdf');
