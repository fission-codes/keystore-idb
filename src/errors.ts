import { KeyUse } from './types'

export const ECCNotEnabled = new Error("ECC is not enabled for this browser. Please use RSA instead.")
export const UnsupportedCrypto = new Error("Cryptosystem not supported. Please use ECC or RSA")
export const InvalidKeyUse = new Error("Invalid key use. Please use 'read' or 'write")

export function checkValidKeyUse(use: KeyUse) {
  if(use !== KeyUse.Read && use !== KeyUse.Write){
    throw InvalidKeyUse
  }
}

export default {
  ECCNotEnabled,
  UnsupportedCrypto,
  InvalidKeyUse,
  checkValidKeyUse,
}
