import aes from '../aes'
import keys from './keys'
import utils, { normalizeBase64ToBuf, normalizeUnicodeToBuf } from '../utils'
import { DEFAULT_CHAR_SIZE, DEFAULT_EccCurve, DEFAULT_HASH_ALG, ECC_READ_ALG, ECC_WRITE_ALG, DEFAULT_SYMM_ALG, DEFAULT_SYMM_LEN } from '../constants'
import { CharSize, Config, EccCurve, Msg, PrivateKey, PublicKey, HashAlg, KeyUse, SymmKey, SymmKeyOpts, CipherText } from '../types'
import config, { defaultConfig } from '../config'


export async function sign(
  msg: Msg,
  privateKey: PrivateKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG,
): Promise<ArrayBuffer> {
  return window.crypto.subtle.sign(
    { name: ECC_WRITE_ALG, hash: { name: hashAlg }},
    privateKey,
    normalizeUnicodeToBuf(msg, charSize)
  )
}

export async function verify(
  msg: Msg,
  sig: Msg,
  publicKey: string | PublicKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE,
  curve: EccCurve = DEFAULT_EccCurve,
  hashAlg: HashAlg = DEFAULT_HASH_ALG
): Promise<boolean> {
  return window.crypto.subtle.verify(
    { name: ECC_WRITE_ALG, hash: { name: hashAlg }},
    typeof publicKey === "string"
      ? await keys.importPublicKey(publicKey, curve, KeyUse.Write)
      : publicKey,
    normalizeBase64ToBuf(sig),
    normalizeUnicodeToBuf(msg, charSize)
  )
}

export async function encrypt(
  msg: Msg,
  privateKey: PrivateKey,
  publicKey: string | PublicKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE,
  curve: EccCurve = DEFAULT_EccCurve,
  opts?: Partial<SymmKeyOpts>
): Promise<ArrayBuffer> {
  const importedPublicKey = typeof publicKey === "string"
    ? await keys.importPublicKey(publicKey, curve, KeyUse.Read)
    : publicKey

  const cipherKey = await getSharedKey(privateKey, importedPublicKey, opts)
  return aes.encryptBytes(normalizeUnicodeToBuf(msg, charSize), cipherKey, opts)
}

export async function decrypt(
  msg: Msg,
  privateKey: PrivateKey,
  publicKey: string | PublicKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE,
  curve: EccCurve = DEFAULT_EccCurve,
  opts?: Partial<SymmKeyOpts>
): Promise<ArrayBuffer> {
  const importedPublicKey = typeof publicKey === "string"
    ? await keys.importPublicKey(publicKey, curve, KeyUse.Read)
    : publicKey

  const cipherKey = await getSharedKey(privateKey, importedPublicKey, opts)
  return aes.decryptBytes(normalizeUnicodeToBuf(msg, charSize), cipherKey, opts)
}

export async function getPublicKey(keypair: CryptoKeyPair): Promise<string> {
  const raw = await window.crypto.subtle.exportKey('raw', keypair.publicKey)
  return utils.arrBufToBase64(raw)
}

export async function getSharedKey(privateKey: PrivateKey, publicKey: PublicKey, opts?: Partial<SymmKeyOpts>): Promise<SymmKey> {
  return window.crypto.subtle.deriveKey(
    { name: ECC_READ_ALG, public: publicKey },
    privateKey,
    {
      name: opts?.alg || DEFAULT_SYMM_ALG,
      length: opts?.length || DEFAULT_SYMM_LEN
    },
    false,
    ['encrypt', 'decrypt']
  )
}

export default {
  sign,
  verify,
  encrypt,
  decrypt,
  getPublicKey,
  getSharedKey
}
