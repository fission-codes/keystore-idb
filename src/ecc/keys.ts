import IDB from '../idb'
import { ECC_READ_ALG, ECC_WRITE_ALG } from '../constants'

export async function getReadKey(curve: ECC_Curve, keyName: string): Promise<EcdhKeyPair> {
  const maybeKey = await IDB.getKey(keyName)
  if(maybeKey){
    return maybeKey
  }
  const keypair = await makeReadKey(curve)
  await IDB.putKey(keyName, keypair)
  return keypair
}

export async function getWriteKey(curve: ECC_Curve, keyName: string): Promise<EcdsaKeyPair> {
  const maybeKey = await IDB.getKey(keyName)
  if(maybeKey){
    return maybeKey
  }
  const keypair = await makeWriteKey(curve)
  await IDB.putKey(keyName, keypair)
  return keypair
}

export async function makeReadKey(curve: ECC_Curve): Promise<EcdhKeyPair> {
  return crypto.subtle.generateKey(
    { name: ECC_READ_ALG, namedCurve: curve },
    false, 
    ['deriveKey', 'deriveBits']
  ) 
}

export async function makeWriteKey(curve: ECC_Curve): Promise<EcdsaKeyPair> {
  return crypto.subtle.generateKey(
    { name: ECC_WRITE_ALG, namedCurve: curve },
    false, 
    ['sign', 'verify']
  ) 
}

export default {
  getReadKey,
  getWriteKey,
  makeReadKey,
  makeWriteKey,
}
