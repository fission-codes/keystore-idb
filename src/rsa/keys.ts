import { RSA_READ_ALG, RSA_WRITE_ALG } from '../constants'
import { RsaSize, HashAlg, KeyUse, PublicKey } from '../types'
import utils from '../utils'
import { checkValidKeyUse } from '../errors'

export async function makeKeypair(
  size: RsaSize,
  hashAlg: HashAlg,
  use: KeyUse
): Promise<CryptoKeyPair> {
  checkValidKeyUse(use)
  const alg = use === KeyUse.Read ? RSA_READ_ALG : RSA_WRITE_ALG
  const uses: KeyUsage[] = use === KeyUse.Read ? ['encrypt', 'decrypt'] : ['sign', 'verify']
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

function stripKeyHeader(base64Key: string): string{
  return base64Key
    .replace('-----BEGIN PUBLIC KEY-----\n', '')
    .replace('\n-----END PUBLIC KEY-----', '')
}

export async function importPublicKey(base64Key: string, hashAlg: HashAlg, use: KeyUse): Promise<PublicKey> {
  checkValidKeyUse(use)
  const alg = use === KeyUse.Read ? RSA_READ_ALG : RSA_WRITE_ALG
  const uses: KeyUsage[] = use === KeyUse.Read ? ['encrypt'] : ['verify']
  const buf = utils.base64ToArrBuf(stripKeyHeader(base64Key))
  return window.crypto.subtle.importKey(
    'spki',
    buf,
    { name: alg, hash: {name: hashAlg}},
    true,
    uses
  )
}

export default {
  makeKeypair,
  importPublicKey
}
