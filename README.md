# IndexedDB KeyStore

[![Build Status](https://travis-ci.org/fission-suite/keystore-idb.svg?branch=master)](https://travis-ci.org/fission-suite/PROJECTNAME)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/fission-suite/blob/master/LICENSE)
[![Maintainability](https://api.codeclimate.com/v1/badges/44fb6a8a0cfd88bc41ef/maintainability)](https://codeclimate.com/github/fission-suite/PROJECTNAME/maintainability)
[![Built by FISSION](https://img.shields.io/badge/⌘-Built_by_FISSION-purple.svg)](https://fission.codes)
[![Discord](https://img.shields.io/discord/478735028319158273.svg)](https://discord.gg/zAQBDEq)
[![Discourse](https://img.shields.io/discourse/https/talk.fission.codes/topics)](https://talk.fission.codes)

In-browser key management with IndexedDB and the Web Crypto API.

Securely store and use keys for encryption, decryption, and signatures.  IndexedDB and Web Crypto keep keys safe from malicious javascript.

Supports both RSA (RSA-PSS & RSA-OAEP) and Elliptic Curves (P-256, P-381 & P-521).

ECC (Elliptic Curve Cryptography) is only available on Chrome. Firefox and Safari do not support ECC and must use RSA.

## Config
Below is the default config and all possible values

```typescript
const defaultConfig = {
  type: 'ecc', // 'ecc' | 'rsa'
  curve: 'P-256', // 'P-256' | 'P-384' | 'P-521'
  rsaSize: 2048, // 1024 | 2048 | 4096
  symmAlg: 'AES-CTR', // 'AES-CTR' | 'AES-GCM' | 'AES-CBC'
  hashAlg: 'SHA-256', // 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
  readKeyName: 'read-key', // any string
  writeKeyName: 'write-key', // any string
}
```
_Note: if you don't include a crypto "type" (`'ecc' | 'rsa'`), the library will check if your browser supports ECC. If so (Chrome), it will use ECC, if not (Firefox, Safari) it will fall back to RSA._

## Example Usage
```typescript
  import KeyStore from './keystore'

  const ALG = 'rsa'
  await KeyStore.clear()
  const ks1 = await KeyStore.init({ type: ALG, readKeyName: 'read-key-1', writeKeyName: 'write-key-1' })
  const ks2 = await KeyStore.init({ type: ALG, readKeyName: 'read-key-2', writeKeyName: 'write-key-2' })

  const msg = "Incididunt id ullamco et do."
  const readKey1 = ks1.readKey
  const readKey2 = ks2.readKey
  const writeKey1 = ks1.writeKey

  const sig = await ks1.sign(msg)
  const valid = await ks2.verify(msg, sig, writeKey1.publicKey)
  console.log('sig: ', sig)
  console.log('valid: ', valid)

  const cipher = await ks1.encrypt(msg, readKey2.publicKey)
  const decipher = await ks2.decrypt(cipher, readKey1.publicKey)
  console.log('cipher: ', cipher)
  console.log('decipher: ', decipher)
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
```
