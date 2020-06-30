import keys from './keys'
import utils, { normalizeUnicodeToBuf } from '../utils'
import { DEFAULT_CHAR_SIZE, DEFAULT_HASH_ALG, RSA_READ_ALG, RSA_WRITE_ALG, SALT_LENGTH } from '../constants'
import { Config, HashAlg, KeyUse, Msg, PrivateKey, PublicKey, CipherText } from '../types'
import { defaultConfig } from '../config'


export async function sign(
  msg: Msg,
  privateKey: PrivateKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE
): Promise<ArrayBuffer> {
  return window.crypto.subtle.sign(
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
  return window.crypto.subtle.verify(
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
): Promise<CipherText> {
  return window.crypto.subtle.encrypt(
    { name: RSA_READ_ALG },
    typeof publicKey === "string"
      ? await keys.importPublicKey(publicKey, hashAlg, KeyUse.Write)
      : publicKey,
    normalizeUnicodeToBuf(msg, charSize)
  )
}

export async function decrypt(
  msg: Msg,
  privateKey: PrivateKey
): Promise<ArrayBuffer> {
  return window.crypto.subtle.decrypt(
    { name: RSA_READ_ALG },
    privateKey,
    normalizeBase64ToBuf(msg)
  )
}

export async function getPublicKey(keypair: CryptoKeyPair): Promise<string> {
  const spki = await window.crypto.subtle.exportKey('spki', keypair.publicKey)
  return utils.arrBufToBase64(spki)
}

export default {
  signBytes,
  signString,
  verifyBytes,
  verifyString,
  encryptBytes,
  encryptString,
  decryptBytes,
  decryptString,
  getPublicKey,
}
