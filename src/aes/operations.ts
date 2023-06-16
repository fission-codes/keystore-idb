import { webcrypto } from 'one-webcrypto'
import keys from './keys.js'
import utils from '../utils.js'
import { DEFAULT_SYMM_ALG, DEFAULT_CTR_LEN } from '../constants.js'
import { CipherText, CryptoConfig, Msg, SymmKey, SymmKeyOpts, SymmAlg } from "../types.js";

export async function encryptBytes(
  msg: Msg,
  key: SymmKey | string,
  opts?: Partial<SymmKeyOpts & CryptoConfig>
): Promise<CipherText> {
  const crypto = opts?.crypto ?? webcrypto
  const data = utils.normalizeUtf16ToBuf(msg)
  const importedKey = typeof key === 'string' ? await keys.importKey(key, opts) : key
  const alg = opts?.alg || DEFAULT_SYMM_ALG
  const iv = opts?.iv || utils.randomBuf(16)
  const cipherBuf = await crypto.subtle.encrypt(
    {
      name: alg,
      // AES-CTR uses a counter, AES-GCM/AES-CBC use an initialization vector
      iv: alg === SymmAlg.AES_CTR ? undefined : iv,
      counter: alg === SymmAlg.AES_CTR ? new Uint8Array(iv) : undefined,
      length: alg === SymmAlg.AES_CTR ? DEFAULT_CTR_LEN : undefined,
    },
    importedKey,
    data
  );
  return utils.joinBufs(iv, cipherBuf)
}

export async function decryptBytes(
  msg: Msg,
  key: SymmKey | string,
  opts?: Partial<SymmKeyOpts & CryptoConfig>
): Promise<ArrayBuffer> {
  const crypto = opts?.crypto ?? webcrypto
  const cipherText = utils.normalizeBase64ToBuf(msg)
  const importedKey = typeof key === 'string' ? await keys.importKey(key, opts) : key
  const alg = opts?.alg || DEFAULT_SYMM_ALG
  const iv = cipherText.slice(0, 16)
  const cipherBytes = cipherText.slice(16)
  const msgBuff = await crypto.subtle.decrypt(
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
  opts?: Partial<SymmKeyOpts & CryptoConfig>
): Promise<string> {
  const cipherText = await encryptBytes(msg, key, opts)
  return utils.arrBufToBase64(cipherText)
}

export async function decrypt(
  msg: Msg,
  key: SymmKey | string,
  opts?: Partial<SymmKeyOpts & CryptoConfig>
): Promise<string> {
  const msgBytes = await decryptBytes(msg, key, opts)
  return utils.arrBufToStr(msgBytes, 16)
}


export async function exportKey(key: SymmKey, opts?: CryptoConfig): Promise<string> {
  const crypto = opts?.crypto ?? webcrypto
  const raw = await crypto.subtle.exportKey('raw', key)
  return utils.arrBufToBase64(raw)
}

export default {
  encryptBytes,
  decryptBytes,
  encrypt,
  decrypt,
  exportKey
}
