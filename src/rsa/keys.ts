import IDB from '../idb'
import { RSA_READ_ALG, RSA_WRITE_ALG } from '../constants'
import { RSA_Size, HashAlg, KeyUse, PublicKey } from '../types'
import utils from '../utils'
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
      publicExponent: utils.publicExponent(),
      hash: { name: hashAlg }
    },
    false,
    uses
  )
}

export async function importPublicKey(hexKey: string, hashAlg: HashAlg, use: KeyUse): Promise<PublicKey> {
  checkValidKeyUse(use)
  const alg = use === KeyUse.Read ? RSA_READ_ALG : RSA_WRITE_ALG
  const uses = use === KeyUse.Read ? ['encrypt'] : ['verify']
  const buf = utils.base64ToArrBuf(stripKeyHeader(hexKey))
  return window.crypto.subtle.importKey(
    'spki',
    buf,
    { name: alg, hash: {name: hashAlg}},
    true,
    uses
  )
}

function stripKeyHeader(hexKey: string): string{
  return hexKey
    .replace('-----BEGIN PUBLIC KEY-----\n', '')
    .replace('\n-----END PUBLIC KEY-----', '')
}

export default {
  getKey,
  makeKey,
  importPublicKey
}
