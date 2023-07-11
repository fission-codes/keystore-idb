import { KeyUse, CryptoSystem } from './types.js'

export const KeyDoesNotExist = new Error("Key does not exist. Make sure you properly instantiated the keystore.")
export const NotKeyPair = new Error("Retrieved a symmetric key when an asymmetric keypair was expected. Please use a different key name.")
export const NotKey = new Error("Retrieved an asymmetric keypair when an symmetric key was expected. Please use a different key name.")
export const ECCNotEnabled = new Error("ECC is not enabled for this browser.")
export const UnsupportedAsymmCrypto = new Error("Cryptosystem not supported. Please use ECC")
export const UnsupportedSymmCrypto = new Error("Cryptosystem not supported. Please use AES-GCM")
export const UnsupportedSymmWrappingCrypto = new Error("Cryptosystem not supported. Please use AES-KW")
export const UnsupportedKeyFormat = new Error("Key format not supported for this cryptosystem or operation")
export const InvalidKeyUse = new Error("Invalid key use. Please use 'exchange' or 'write")
export const InvalidMaxValue = new Error("Max must be less than 256 and greater than 0")
export const InvalidIvLength = new Error("IV must be 16 bytes")
export const InvalidCipherTextLength = new Error("Cipher text must align on AES-GCM block (16 bytes) boundary")

export function checkIsKeyPair(keypair: any): CryptoKeyPair {
  if (!keypair || keypair === null) {
    throw KeyDoesNotExist
  } else if (keypair.privateKey === undefined) {
    throw NotKeyPair
  }
  return keypair as CryptoKeyPair
}

export function checkIsKey(key: any): CryptoKey {
  if (!key || key === null) {
    throw KeyDoesNotExist
  } else if (key.privateKey !== undefined || key.algorithm === undefined) {
    throw NotKey
  }
  return key
}

export function checkValidCryptoSystem(type: CryptoSystem): void {
  checkValid(type, [CryptoSystem.ECC, CryptoSystem.RSA], UnsupportedAsymmCrypto)
}

export function checkValidKeyUse(use: KeyUse): void {
  checkValid(use, [KeyUse.Exchange, KeyUse.Write], InvalidKeyUse)
}

function checkValid<T>(toCheck: T, opts: T[], error: Error): void {
  const match = opts.some(opt => opt === toCheck)
  if (!match) {
    throw error
  }
}

export default {
  KeyDoesNotExist,
  NotKeyPair,
  NotKey,
  ECCNotEnabled,
  UnsupportedAsymmCrypto,
  InvalidKeyUse,
  checkIsKeyPair,
  checkIsKey,
  checkValidCryptoSystem,
  checkValidKeyUse,
  InvalidMaxValue,
  InvalidIvLength,
  InvalidCipherTextLength
}
