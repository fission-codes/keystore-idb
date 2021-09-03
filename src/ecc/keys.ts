import utils from '../utils'
import { ECC_READ_ALG, ECC_WRITE_ALG } from '../constants'
import { EccCurve, KeyUse, PublicKey } from '../types'
import { checkValidKeyUse } from '../errors'

export async function makeKeypair(
  curve: EccCurve,
  use: KeyUse
): Promise<CryptoKeyPair> {
  checkValidKeyUse(use)
  const alg = use === KeyUse.Exchange ? ECC_READ_ALG : ECC_WRITE_ALG
  const uses: KeyUsage[] =
    use === KeyUse.Exchange ? ['deriveKey', 'deriveBits'] : ['sign', 'verify']
  return globalThis.crypto.subtle.generateKey(
    { name: alg, namedCurve: curve },
    false,
    uses
  )
}

export async function importPublicKey(base64Key: string, curve: EccCurve, use: KeyUse): Promise<PublicKey> {
  checkValidKeyUse(use)
  const alg = use === KeyUse.Exchange ? ECC_READ_ALG : ECC_WRITE_ALG
  const uses: KeyUsage[] =
    use === KeyUse.Exchange ? [] : ['verify']
  const buf = utils.base64ToArrBuf(base64Key)
  return globalThis.crypto.subtle.importKey(
    'raw',
    buf,
    { name: alg, namedCurve: curve },
    true,
    uses
  )
}

export default {
  makeKeypair,
  importPublicKey
}
