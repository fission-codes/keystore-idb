import { RSA_EXCHANGE_ALG, RSA_WRITE_ALG } from '../constants.js'
import { RsaSize, HashAlg, KeyUse, PublicKey } from '../types.js'
import utils from '../utils.js'
import { checkValidKeyUse } from '../errors.js'
import { webcrypto } from '../webcrypto.js'

export async function makeKeypair(
  size: RsaSize,
  hashAlg: HashAlg,
  use: KeyUse
): Promise<CryptoKeyPair> {
  checkValidKeyUse(use)
  const alg = use === KeyUse.Exchange ? RSA_EXCHANGE_ALG : RSA_WRITE_ALG
  const uses: KeyUsage[] = use === KeyUse.Exchange ? ['encrypt', 'decrypt'] : ['sign', 'verify']
  return webcrypto.generateKey(
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
  const alg = use === KeyUse.Exchange ? RSA_EXCHANGE_ALG : RSA_WRITE_ALG
  const uses: KeyUsage[] = use === KeyUse.Exchange ? ['encrypt'] : ['verify']
  const buf = utils.base64ToArrBuf(stripKeyHeader(base64Key))
  return webcrypto.importKey(
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
