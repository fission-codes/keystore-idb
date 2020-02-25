import { KeyUse } from './types'

export const InvalidKeyUse = new Error("Invalid key use. Please use 'read' or 'write")

export function checkValidKeyUse(use: KeyUse) {
  if(use !== KeyUse.Read && use !== KeyUse.Write){
    throw InvalidKeyUse
  }
}

export default {
  InvalidKeyUse,
  checkValidKeyUse,
}
