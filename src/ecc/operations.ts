import aes from '../aes/index.js'
import keys from './keys.js'
import utils, { normalizeBase64ToBuf, normalizeUnicodeToBuf } from '../utils.js'
import { DEFAULT_CHAR_SIZE, DEFAULT_ECC_CURVE, DEFAULT_HASH_ALG, ECC_EXCHANGE_ALG, ECC_WRITE_ALG, DEFAULT_SYMM_ALG, DEFAULT_SYMM_LEN } from '../constants.js'
import { CharSize, EccCurve, Msg, PrivateKey, PublicKey, HashAlg, KeyUse, SymmKey, SymmKeyOpts } from '../types.js'
import { webcrypto } from 'one-webcrypto'


export async function sign(
  msg: Msg,
  privateKey: PrivateKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG,
): Promise<ArrayBuffer> {
  return webcrypto.subtle.sign(
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
  curve: EccCurve = DEFAULT_ECC_CURVE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG
): Promise<boolean> {
  return webcrypto.subtle.verify(
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
  curve: EccCurve = DEFAULT_ECC_CURVE,
  opts?: Partial<SymmKeyOpts>
): Promise<ArrayBuffer> {
  const importedPublicKey = typeof publicKey === "string"
    ? await keys.importPublicKey(publicKey, curve, KeyUse.Exchange)
    : publicKey

  const cipherKey = await getSharedKey(privateKey, importedPublicKey, opts)
  return aes.encryptBytes(normalizeUnicodeToBuf(msg, charSize), cipherKey, opts)
}

export async function decrypt(
  msg: Msg,
  privateKey: PrivateKey,
  publicKey: string | PublicKey,
  curve: EccCurve = DEFAULT_ECC_CURVE,
  opts?: Partial<SymmKeyOpts>
): Promise<ArrayBuffer> {
  const importedPublicKey = typeof publicKey === "string"
    ? await keys.importPublicKey(publicKey, curve, KeyUse.Exchange)
    : publicKey

  const cipherKey = await getSharedKey(privateKey, importedPublicKey, opts)
  return aes.decryptBytes(normalizeBase64ToBuf(msg), cipherKey, opts)
}

export async function getPublicKey(keypair: CryptoKeyPair): Promise<string> {
  const raw = await webcrypto.subtle.exportKey('raw', keypair.publicKey as PublicKey)
  return utils.arrBufToBase64(raw)
}

export async function getSharedKey(privateKey: PrivateKey, publicKey: PublicKey, opts?: Partial<SymmKeyOpts>): Promise<SymmKey> {
  return webcrypto.subtle.deriveKey(
    { name: ECC_EXCHANGE_ALG, public: publicKey },
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
