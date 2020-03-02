import { KeyUse, CryptoSystem } from './types'

export const ECCNotEnabled = new Error("ECC is not enabled for this browser. Please use RSA instead.")
export const UnsupportedCrypto = new Error("Cryptosystem not supported. Please use ECC or RSA")
export const InvalidKeyUse = new Error("Invalid key use. Please use 'read' or 'write")

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
  ECCNotEnabled,
  UnsupportedCrypto,
  InvalidKeyUse,
  checkValidKeyUse,
}
