import keys from './keys.js'
import utils, { normalizeBase64ToBuf, normalizeUnicodeToBuf } from '../utils.js'
import { DEFAULT_CHAR_SIZE, DEFAULT_HASH_ALG, RSA_EXCHANGE_ALG, RSA_WRITE_ALG, SALT_LENGTH } from '../constants.js'
import { CharSize, HashAlg, KeyUse, Msg, PrivateKey, PublicKey } from '../types.js'
import { webcrypto } from 'one-webcrypto'


export async function sign(
  msg: Msg,
  privateKey: PrivateKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE
): Promise<ArrayBuffer> {
  return webcrypto.subtle.sign(
    { name: RSA_WRITE_ALG, saltLength: SALT_LENGTH },
    privateKey,
    normalizeUnicodeToBuf(msg, charSize)
  )
}

export async function verify(
  msg: Msg,
  sig: Msg,
  publicKey: string | PublicKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG
): Promise<boolean> {
  return webcrypto.subtle.verify(
    { name: RSA_WRITE_ALG, saltLength: SALT_LENGTH },
    typeof publicKey === "string"
      ? await keys.importPublicKey(publicKey, hashAlg, KeyUse.Write)
      : publicKey,
    normalizeBase64ToBuf(sig),
    normalizeUnicodeToBuf(msg, charSize)
  )
}

export async function encrypt(
  msg: Msg,
  publicKey: string | PublicKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG
): Promise<ArrayBuffer> {
  return webcrypto.subtle.encrypt(
    { name: RSA_EXCHANGE_ALG },
    typeof publicKey === "string"
      ? await keys.importPublicKey(publicKey, hashAlg, KeyUse.Exchange)
      : publicKey,
    normalizeUnicodeToBuf(msg, charSize)
  )
}

export async function decrypt(
  msg: Msg,
  privateKey: PrivateKey
): Promise<ArrayBuffer> {
  const normalized = normalizeBase64ToBuf(msg)
  return webcrypto.subtle.decrypt(
    { name: RSA_EXCHANGE_ALG },
    privateKey,
    normalized
  )
}

export async function getPublicKey(keypair: CryptoKeyPair): Promise<string> {
  const spki = await webcrypto.subtle.exportKey('spki', keypair.publicKey as PublicKey)
  return utils.arrBufToBase64(spki)
}

export default {
  sign,
  verify,
  encrypt,
  decrypt,
  getPublicKey,
}
