import * as uint8arrays from "uint8arrays"
import { webcrypto } from 'one-webcrypto'

import aes from '../aes/index.js'
import keys from './keys.js'
import { normalizeAssumingBase64, normalizeAssumingUtf8 } from '../utils.js'
import { DEFAULT_ECC_CURVE, DEFAULT_HASH_ALG, ECC_EXCHANGE_ALG, ECC_WRITE_ALG, DEFAULT_SYMM_ALG, DEFAULT_SYMM_LEN } from '../constants.js'
import { EccCurve, Msg, PrivateKey, PublicKey, HashAlg, KeyUse, SymmKey, SymmKeyOpts } from '../types.js'


export async function sign(
  msg: Msg,
  privateKey: PrivateKey,
  hashAlg: HashAlg = DEFAULT_HASH_ALG,
): Promise<Uint8Array> {
  return new Uint8Array(await webcrypto.subtle.sign(
    { name: ECC_WRITE_ALG, hash: { name: hashAlg }},
    privateKey,
    normalizeAssumingUtf8(msg)
  ))
}

export async function verify(
  msg: Msg,
  sig: Msg,
  publicKey: string | PublicKey,
  curve: EccCurve = DEFAULT_ECC_CURVE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG
): Promise<boolean> {
  return webcrypto.subtle.verify(
    { name: ECC_WRITE_ALG, hash: { name: hashAlg }},
    typeof publicKey === "string"
      ? await keys.importPublicKey(publicKey, curve, KeyUse.Write)
      : publicKey,
    normalizeAssumingBase64(sig),
    normalizeAssumingUtf8(msg)
  )
}

export async function encrypt(
  msg: Msg,
  privateKey: PrivateKey,
  publicKey: string | PublicKey,
  curve: EccCurve = DEFAULT_ECC_CURVE,
  opts?: Partial<SymmKeyOpts>
): Promise<Uint8Array> {
  const importedPublicKey = typeof publicKey === "string"
    ? await keys.importPublicKey(publicKey, curve, KeyUse.Exchange)
    : publicKey

  const cipherKey = await getSharedKey(privateKey, importedPublicKey, opts)
  return aes.encryptBytes(normalizeAssumingUtf8(msg), cipherKey, opts)
}

export async function decrypt(
  msg: Msg,
  privateKey: PrivateKey,
  publicKey: string | PublicKey,
  curve: EccCurve = DEFAULT_ECC_CURVE,
  opts?: Partial<SymmKeyOpts>
): Promise<Uint8Array> {
  const importedPublicKey = typeof publicKey === "string"
    ? await keys.importPublicKey(publicKey, curve, KeyUse.Exchange)
    : publicKey

  const cipherKey = await getSharedKey(privateKey, importedPublicKey, opts)
  return aes.decryptBytes(normalizeAssumingBase64(msg), cipherKey, opts)
}

export async function getPublicKey(keypair: CryptoKeyPair): Promise<string> {
  const raw = await webcrypto.subtle.exportKey('raw', keypair.publicKey as PublicKey)
  return uint8arrays.toString(new Uint8Array(raw), "base64pad")
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
