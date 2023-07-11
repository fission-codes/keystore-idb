# Banyan KeyStore

<!-- [![NPM](https://img.shields.io/npm/v/keystore-idb)](https://www.npmjs.com/package/keystore-idb)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/fission-suite/blob/master/LICENSE)
[![Maintainability](https://api.codeclimate.com/v1/badges/b0fabd7e80c6bd2c0c7b/maintainability)](https://codeclimate.com/github/fission-suite/keystore-idb/maintainability)
[![Built by FISSION](https://img.shields.io/badge/⌘-Built_by_FISSION-purple.svg)](https://fission.codes)
[![Discord](https://img.shields.io/discord/478735028319158273.svg)](https://discord.gg/zAQBDEq)
[![Discourse](https://img.shields.io/discourse/https/talk.fission.codes/topics)](https://talk.fission.codes) -->

In-browser key management with IndexedDB and the Web Crypto API.

Securely store and use keys for encryption, decryption, and signatures. IndexedDB and Web Crypto keep keys safe from malicious javascript.

Supports ~both RSA (RSASSA-PKCS1-v1_5 & RSA-OAEP) and Elliptic Curves (P-256, P-381 & P-521)~ only EC (P-381 & P-521) keys.

## Config

Below is the default config and all possible values
_Note: these are given as primitives, but in Typescript you can use the included enums_

```typescript
const defaultConfig = {
  curve: 'P-384', // 'P-384' | 'P-521'
  symmAlg: 'AES-GCM', // AES-GCM only
  symmWrappingAlg: 'AES-KW', // AES-KW only
  symmKeyLength: 256, // 256 | 384 | 512
  saltLength: 128, // 128 | 256
  hashAlg: 'SHA-256', // 'SHA-256' | 'SHA-384' | 'SHA-512'
  charSize: 16, // 8 | 16
  storeName: 'keystore', // any string
  exchangeKeyName: 'exchange-key-pair', // any string
  writeKeyName: 'write-key-pair', // any string
  passKeyName: 'pass-key', // any string
}
```
_Note: the library will check if your browser supports ECC. If so it will use ECC, if not it will use raise an error_


## Example Usage

```typescript
import Keystore from 'banyan-keystore'

async function run() {
  const ks = await Keystore.init()

  const msg = "Incididunt id ullamco et do."

  // TODO

  await ks.clear()
}

run()
```



## Development

```shell
# install dependencies
yarn

# run development server
yarn start

# build
yarn build

# test
# Note use nodeV16 when running tests
yarn test

# test w/ reloading
yarn test:watch

# publish (run this script instead of npm publish!)
./publish.sh
```
