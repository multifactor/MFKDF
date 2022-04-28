## Download MFKDF.js
There are three ways to add `mfkdf.js` to your project: self-hosted, using a CDN, or using NPM (recommended).

### Option 1: Self-Hosted
First download the [latest release on GitHub](https://github.com/multifactor/MFKDF/releases), then add `mfkdf.js` or `mfkdf.min.js` to your page like so:

	<script src="mfkdf.min.js"></script>

### Option 2: CDN
You can automatically include the latest version of `mfkdf.min.js` in your page like so:

	<script src="https://cdn.jsdelivr.net/gh/multifactor/mfkdf/mfkdf.min.js"></script>

Note that this may automatically update to include breaking changes in the future. Therefore, it is recommended that you get the latest single-version tag with SRI from [jsDelivr](https://www.jsdelivr.com/package/npm/mfkdf) instead.

### Option 3: NPM (recommended)
Add MFKDF to your NPM project:

	npm install mfkdf


Require MFKDF like so:

	const mfkdf = require('mfkdf');
