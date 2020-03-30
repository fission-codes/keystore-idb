import IDB from '../idb'
import utils from '../utils'
import { ECC_READ_ALG, ECC_WRITE_ALG } from '../constants'
import { EccCurve, KeyUse, PublicKey } from '../types'
import { checkValidKeyUse, checkIsKeyPair } from '../errors'

export async function makeKey(
  curve: EccCurve,
  use: KeyUse
): Promise<CryptoKeyPair> {
  checkValidKeyUse(use)
  const alg = use === KeyUse.Read ? ECC_READ_ALG : ECC_WRITE_ALG
  const uses =
    use === KeyUse.Read ? ['deriveKey', 'deriveBits'] : ['sign', 'verify']
  return window.crypto.subtle.generateKey(
    { name: alg, namedCurve: curve },
    false,
    uses
  )
}

export async function getKey(
  curve: EccCurve,
  keyName: string,
  use: KeyUse
): Promise<CryptoKeyPair> {
  checkValidKeyUse(use)
  const maybeKey = await IDB.getKey(keyName)
  if (maybeKey) {
    return checkIsKeyPair(maybeKey) 
  }
  const keypair = await makeKey(curve, use)
  await IDB.putKey(keyName, keypair)
  return keypair
}

export async function importPublicKey(base64Key: string, curve: EccCurve, use: KeyUse): Promise<PublicKey> {
  checkValidKeyUse(use)
  const alg = use === KeyUse.Read ? ECC_READ_ALG : ECC_WRITE_ALG
  const uses =
    use === KeyUse.Read ? [] : ['verify']
  const buf = utils.base64ToArrBuf(base64Key)
  return window.crypto.subtle.importKey(
    'raw',
    buf,
    { name: alg, namedCurve: curve },
    true,
    uses
  )
}

export default {
  makeKey,
  getKey,
  importPublicKey
}
