import { KeyUse, CryptoSystem } from './types'

export const NotKeyPair = new Error("Retrieved a symmetric key when an asymmetric keypair was expected. Please use a different key name.")
export const NotKey = new Error("Retrieved an asymmetric keypair when an symmetric key was expected. Please use a different key name.")
export const ECCNotEnabled = new Error("ECC is not enabled for this browser. Please use RSA instead.")
export const UnsupportedCrypto = new Error("Cryptosystem not supported. Please use ECC or RSA")
export const InvalidKeyUse = new Error("Invalid key use. Please use 'read' or 'write")

export function checkIsKeyPair(keypair: any): CryptoKeyPair {
  if(keypair.privateKey === undefined){
    throw NotKeyPair
  }
  return keypair as CryptoKeyPair
}

export function checkIsKey(key: any): CryptoKey {
  if(key.privateKey !== undefined || key.algorithm === undefined){
    throw NotKey
  }
  return key
}

export function checkValidCryptoSystem(type: CryptoSystem): void {
  checkValid(type, [CryptoSystem.ECC, CryptoSystem.RSA], UnsupportedCrypto)
}

export function checkValidKeyUse(use: KeyUse): void {
  checkValid(use, [KeyUse.Read, KeyUse.Write], InvalidKeyUse)
}

function checkValid<T>(toCheck: T, opts: T[], error: Error): void {
  const match = opts.some(opt => opt === toCheck)
  if(!match) {
    throw error
  }
}

export default {
  NotKeyPair,
  NotKey,
  ECCNotEnabled,
  UnsupportedCrypto,
  InvalidKeyUse,
  checkIsKeyPair,
  checkIsKey,
  checkValidCryptoSystem,
  checkValidKeyUse,
}
