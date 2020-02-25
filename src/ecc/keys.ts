import IDB from '../idb'
import { ECC_READ_ALG, ECC_WRITE_ALG } from '../constants'

export async function getKey(
  curve: ECC_Curve,
  keyName: string,
  use: KeyUse
): Promise<CryptoKeyPair> {
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
  const alg = use === KeyUse.Read ? ECC_READ_ALG : ECC_WRITE_ALG
  const uses =
    use === KeyUse.Read ? ['deriveKey', 'deriveBits'] : ['sign', 'verify']
  return crypto.subtle.generateKey(
    { name: alg, namedCurve: curve },
    false,
    uses
  )
}

export default {
  getKey,
  makeKey
}
