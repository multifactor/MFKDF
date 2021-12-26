# Contributing
Contributions are always welcome. Before contributing, please search the issue tracker; your issue may have already been discussed or fixed in `master`. To contribute, [fork](https://help.github.com/articles/fork-a-repo/) the repository, commit your changes, and [send a pull request](https://help.github.com/articles/using-pull-requests/).

## Feature Requests
Feature requests should be submitted in the issue tracker, with a description of the expected behavior & use case. Before submitting a request, please search for similar ones in the closed issues.

## Pull Requests
For additions or bug fixes you should only need to modify `index.js`. Include updated unit tests in the `test` directory as part of your pull request. Don’t worry about regenerating the `site/` files.

Before running the unit tests you’ll need to install, `npm i`, [development dependencies](https://docs.npmjs.com/files/package.json#devdependencies). Run unit tests from the command-line via `npm test`.

## Coding Guidelines

[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard)

In addition to the following guidelines, please follow the conventions already established in the code.

- **Spacing**:<br>
  Use two spaces for indentation. No tabs.

- **Naming**:<br>
  Keep variable & method names concise & descriptive.<br>
  Variable names `index`, `array`, & `iteratee` are preferable to
  `i`, `arr`, & `fn`.

- **Comments**:<br>
  Please use single-line comments to annotate significant additions, &
  [JSDoc-style](http://www.2ality.com/2011/08/jsdoc-intro.html) comments for
  functions.

Guidelines are enforced using [ESLint](https://www.npmjs.com/package/eslint):
```bash
$ npm run style
```
