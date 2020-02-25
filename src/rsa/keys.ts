import IDB from '../idb'
import { RSA_READ_ALG, RSA_WRITE_ALG } from '../constants'

export async function getKey(
  size: RSA_Size,
  hashAlg: HashAlg,
  keyName: string,
  use: KeyUse
): Promise<CryptoKeyPair> {
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
  const alg = use === KeyUse.Read ? RSA_READ_ALG : RSA_WRITE_ALG
  const uses = use === KeyUse.Read ? ['encrypt', 'decrypt'] : ['sign', 'verify']
  return crypto.subtle.generateKey(
    {
      name: alg,
      modulusLength: size,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
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
