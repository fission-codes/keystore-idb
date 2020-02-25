import IDB from '../idb'
import { RSA_READ_ALG, RSA_WRITE_ALG } from '../constants'
import { RSA_Size, HashAlg, KeyUse } from '../types'
import { publicExponent } from '../utils'
import { checkValidKeyUse } from '../errors'

export async function getKey(
  size: RSA_Size,
  hashAlg: HashAlg,
  keyName: string,
  use: KeyUse
): Promise<CryptoKeyPair> {
  checkValidKeyUse(use)
  const maybeKey = await IDB.getKey(keyName)
  if (maybeKey) {
    return maybeKey
  }
  const keypair = await makeKey(size, hashAlg, use)
  await IDB.putKey(keyName, keypair)
  return keypair
}

export async function makeKey(
  size: RSA_Size,
  hashAlg: HashAlg,
  use: KeyUse
): Promise<CryptoKeyPair> {
  checkValidKeyUse(use)
  const alg = use === KeyUse.Read ? RSA_READ_ALG : RSA_WRITE_ALG
  const uses = use === KeyUse.Read ? ['encrypt', 'decrypt'] : ['sign', 'verify']
  return window.crypto.subtle.generateKey(
    {
      name: alg,
      modulusLength: size,
      publicExponent: publicExponent(),
      hash: { name: hashAlg }
    },
    false,
    uses
  )
}

export default {
  getKey,
  makeKey
}
