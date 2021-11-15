import * as uint8arrays from "uint8arrays"
import { webcrypto } from 'one-webcrypto'

import keys from './keys.js'
import { normalizeBase64ToBuf, normalizeUnicodeToBuf } from '../utils.js'
import { DEFAULT_HASH_ALG, RSA_EXCHANGE_ALG, RSA_WRITE_ALG, SALT_LENGTH } from '../constants.js'
import { HashAlg, KeyUse, Msg, PrivateKey, PublicKey } from '../types.js'


export async function sign(
  msg: Msg,
  privateKey: PrivateKey,
): Promise<ArrayBuffer> {
  return webcrypto.subtle.sign(
    { name: RSA_WRITE_ALG, saltLength: SALT_LENGTH },
    privateKey,
    normalizeUnicodeToBuf(msg)
  )
}

export async function verify(
  msg: Msg,
  sig: Msg,
  publicKey: string | PublicKey,
  hashAlg: HashAlg = DEFAULT_HASH_ALG
): Promise<boolean> {
  return webcrypto.subtle.verify(
    { name: RSA_WRITE_ALG, saltLength: SALT_LENGTH },
    typeof publicKey === "string"
      ? await keys.importPublicKey(publicKey, hashAlg, KeyUse.Write)
      : publicKey,
    normalizeBase64ToBuf(sig),
    normalizeUnicodeToBuf(msg)
  )
}

export async function encrypt(
  msg: Msg,
  publicKey: string | PublicKey,
  hashAlg: HashAlg = DEFAULT_HASH_ALG
): Promise<ArrayBuffer> {
  return webcrypto.subtle.encrypt(
    { name: RSA_EXCHANGE_ALG },
    typeof publicKey === "string"
      ? await keys.importPublicKey(publicKey, hashAlg, KeyUse.Exchange)
      : publicKey,
    normalizeUnicodeToBuf(msg)
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
  return uint8arrays.toString(new Uint8Array(spki), "base64pad")
}

export default {
  sign,
  verify,
  encrypt,
  decrypt,
  getPublicKey,
}
