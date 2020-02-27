import IDB from '../idb'
import utils from '../utils'
import { ECC_READ_ALG, ECC_WRITE_ALG } from '../constants'
import { ECC_Curve, KeyUse, PublicKey } from '../types'
import { checkValidKeyUse } from '../errors'

export async function getKey(
  curve: ECC_Curve,
  keyName: string,
  use: KeyUse
): Promise<CryptoKeyPair> {
  checkValidKeyUse(use)
  const maybeKey = await IDB.getKey(keyName)
  if (maybeKey) {
    return maybeKey
  }
  const keypair = await makeKey(curve, use)
  await IDB.putKey(keyName, keypair)
  return keypair
}

export async function makeKey(
  curve: ECC_Curve,
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

export async function importPublicKey(hexKey: string, curve: ECC_Curve, use: KeyUse): Promise<PublicKey> {
  checkValidKeyUse(use)
  const alg = use === KeyUse.Read ? ECC_READ_ALG : ECC_WRITE_ALG
  const uses =
    use === KeyUse.Read ? [] : ['verify']
  const buf = utils.hexToArrBuf(hexKey)
  return window.crypto.subtle.importKey(
    'raw',
    buf,
    { name: alg, namedCurve: curve },
    true,
    uses
  )
}

export default {
  getKey,
  makeKey,
  importPublicKey
}
