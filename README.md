# IndexedDB KeyStore
  
[![NPM](https://img.shields.io/npm/v/keystore-idb)](https://www.npmjs.com/package/keystore-idb)
[![Build Status](https://travis-ci.org/fission-suite/keystore-idb.svg?branch=master)](https://travis-ci.org/fission-suite/keystore-idb)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/fission-suite/blob/master/LICENSE)
[![Maintainability](https://api.codeclimate.com/v1/badges/b0fabd7e80c6bd2c0c7b/maintainability)](https://codeclimate.com/github/fission-suite/keystore-idb/maintainability)
[![Built by FISSION](https://img.shields.io/badge/⌘-Built_by_FISSION-purple.svg)](https://fission.codes)
[![Discord](https://img.shields.io/discord/478735028319158273.svg)](https://discord.gg/zAQBDEq)
[![Discourse](https://img.shields.io/discourse/https/talk.fission.codes/topics)](https://talk.fission.codes)

In-browser key management with IndexedDB and the Web Crypto API.

Securely store and use keys for encryption, decryption, and signatures.  IndexedDB and Web Crypto keep keys safe from malicious javascript.

Supports both RSA (RSA-PSS & RSA-OAEP) and Elliptic Curves (P-256, P-381 & P-521).

ECC (Elliptic Curve Cryptography) is only available on Chrome. Firefox and Safari do not support ECC and must use RSA.
_Specifically, this is an issue with storing ECC keys in IndexedDB_

## Config
Below is the default config and all possible values
_Note: these are given as primitives, but in Typescript you can use the included enums_

```typescript
const defaultConfig = {
  type: 'ecc', // 'ecc' | 'rsa'
  curve: 'P-256', // 'P-256' | 'P-384' | 'P-521'
  rsaSize: 2048, // 1024 | 2048 | 4096
  symmAlg: 'AES-CTR', // 'AES-CTR' | 'AES-GCM' | 'AES-CBC'
  symmLen: 128, // 128 | 192 | 256
  hashAlg: 'SHA-256', // 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
  readKeyName: 'read-key', // any string
  writeKeyName: 'write-key', // any string
}
```
_Note: if you don't include a crypto "type" (`'ecc' | 'rsa'`), the library will check if your browser supports ECC. If so (Chrome), it will use ECC, if not (Firefox, Safari) it will fall back to RSA._

## Example Usage
```typescript
import keystore from './index'

async function run() {
  const ALG = types.CryptoSystem.ECC
  await keystore.clear()
  const ks1 = await keystore.init({ readKeyName: 'read-key-1', writeKeyName: 'write-key-1' })
  const ks2 = await keystore.init({ readKeyName: 'read-key-2', writeKeyName: 'write-key-2' })

  const msg = "Incididunt id ullamco et do."
  // read keys and write keys are separate because of the Web Crypto API
  const readKey1 = await ks1.publicReadKey()
  const writeKey1 = await ks1.publicWriteKey()
  const readKey2 = await ks2.publicReadKey()
  // these keys get exported as strings
  console.log('readKey1: ', readKey1)
  console.log('writeKey1: ', writeKey1)
  console.log('readKey2: ', readKey2)

  const sig = await ks1.sign(msg)
  const valid = await ks2.verify(msg, sig, writeKey1)
  console.log('sig: ', sig)
  console.log('valid: ', valid)

  const cipher = await ks1.encrypt(msg, readKey2)
  const decipher = await ks2.decrypt(cipher, readKey1)
  console.log('cipher: ', cipher)
  console.log('decipher: ', decipher)
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
yarn test

# test w/ reloading
yarn test:watch

# publish (run this script instead of npm publish!)
./publish.sh
```
