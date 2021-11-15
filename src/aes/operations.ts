import { webcrypto } from 'one-webcrypto'
import * as uint8arrays from "uint8arrays"

import keys from './keys.js'
import utils from '../utils.js'
import { DEFAULT_SYMM_ALG, DEFAULT_CTR_LEN } from '../constants.js'
import { SymmKey, SymmKeyOpts, SymmAlg, CipherText, Msg } from '../types.js'

export async function encryptBytes(
  msg: Msg,
  key: SymmKey | string,
  opts?: Partial<SymmKeyOpts>
): Promise<CipherText> {
  const data = utils.normalizeUnicodeToBuf(msg)
  const importedKey = typeof key === 'string' ? await keys.importKey(key, opts) : key
  const alg = opts?.alg || DEFAULT_SYMM_ALG
  const iv = opts?.iv || utils.randomBuf(16)
  const cipherBuf = await webcrypto.subtle.encrypt(
    {
      name: alg,
      // AES-CTR uses a counter, AES-GCM/AES-CBC use an initialization vector
      iv: alg === SymmAlg.AES_CTR ? undefined : iv,
      counter: alg === SymmAlg.AES_CTR ? new Uint8Array(iv) : undefined,
      length: alg === SymmAlg.AES_CTR ? DEFAULT_CTR_LEN : undefined,
    },
    importedKey,
    data
  )
  return uint8arrays.concat([new Uint8Array(iv), new Uint8Array(cipherBuf)]).buffer
}

export async function decryptBytes(
  msg: Msg,
  key: SymmKey | string,
  opts?: Partial<SymmKeyOpts>
): Promise<ArrayBuffer> {
  const cipherText = utils.normalizeBase64ToBuf(msg)
  const importedKey = typeof key === 'string' ? await keys.importKey(key, opts) : key
  const alg = opts?.alg || DEFAULT_SYMM_ALG
  const iv = cipherText.slice(0, 16)
  const cipherBytes = cipherText.slice(16)
  const msgBuff = await webcrypto.subtle.decrypt(
    { name: alg,
      // AES-CTR uses a counter, AES-GCM/AES-CBC use an initialization vector
      iv: alg === SymmAlg.AES_CTR ? undefined : iv,
      counter: alg === SymmAlg.AES_CTR ? new Uint8Array(iv) : undefined,
      length: alg === SymmAlg.AES_CTR ? DEFAULT_CTR_LEN : undefined,
    },
    importedKey,
    cipherBytes
  )
  return msgBuff
}

export async function encrypt(
  msg: Msg,
  key: SymmKey | string,
  opts?: Partial<SymmKeyOpts>
): Promise<string> {
  const cipherText = await encryptBytes(msg, key, opts)
  return uint8arrays.toString(new Uint8Array(cipherText), "base64pad")
}

export async function decrypt(
  msg: Msg,
  key: SymmKey | string,
  opts?: Partial<SymmKeyOpts>
): Promise<string> {
  const msgBytes = await decryptBytes(msg, key, opts)
  return uint8arrays.toString(new Uint8Array(msgBytes), "utf8")
}


export async function exportKey(key: SymmKey): Promise<string> {
  const raw = await webcrypto.subtle.exportKey('raw', key)
  return uint8arrays.toString(new Uint8Array(raw), "base64pad")
}

export default {
  encryptBytes,
  decryptBytes,
  encrypt,
  decrypt,
  exportKey
}
