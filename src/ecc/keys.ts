import { webcrypto } from 'one-webcrypto'
import * as uint8arrays from "uint8arrays"

import { ECC_EXCHANGE_ALG, ECC_WRITE_ALG } from '../constants.js'
import { EccCurve, KeyUse, PublicKey } from '../types.js'
import { checkValidKeyUse } from '../errors.js'

export async function makeKeypair(
  curve: EccCurve,
  use: KeyUse
): Promise<CryptoKeyPair> {
  checkValidKeyUse(use)
  const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALG : ECC_WRITE_ALG
  const uses: KeyUsage[] =
    use === KeyUse.Exchange ? ['deriveKey', 'deriveBits'] : ['sign', 'verify']
  return webcrypto.subtle.generateKey(
    { name: alg, namedCurve: curve },
    false,
    uses
  )
}

export async function importPublicKey(base64Key: string, curve: EccCurve, use: KeyUse): Promise<PublicKey> {
  checkValidKeyUse(use)
  const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALG : ECC_WRITE_ALG
  const uses: KeyUsage[] =
    use === KeyUse.Exchange ? [] : ['verify']
  const buf = uint8arrays.fromString(base64Key, "base64pad")
  return webcrypto.subtle.importKey(
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
