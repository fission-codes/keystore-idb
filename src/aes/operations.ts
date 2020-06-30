import keys from './keys'
import utils from '../utils'
import { DEFAULT_SYMM_ALG, DEFAULT_SYMM_LEN } from '../constants'
import { SymmKey, SymmKeyOpts, SymmAlg, CipherText, Msg } from '../types'

export async function encryptBytes(
  msg: Msg,
  key: SymmKey | string,
  opts?: Partial<SymmKeyOpts>
): Promise<CipherText> {
  const data = utils.normalizeToBuf(msg)
  const importedKey = typeof key === 'string' ? await keys.importKey(key, opts) : key
  const alg = opts?.alg || DEFAULT_SYMM_ALG
  const iv = opts?.iv || utils.randomBuf(16)
  const cipherBuf = await window.crypto.subtle.encrypt(
    { 
      name: alg,
      length: opts?.length || DEFAULT_SYMM_LEN,
      // AES-CTR uses a counter, AES-GCM/AES-CBC use an initialization vector
      iv: alg === SymmAlg.AES_CTR ? undefined : iv,
      counter: alg === SymmAlg.AES_CTR ? new Uint8Array(iv) : undefined,
    },
    importedKey,
    data
  )
  return utils.joinBufs(iv, cipherBuf)
}

export async function decryptBytes(
  msg: Msg,
  key: SymmKey | string,
  opts?: Partial<SymmKeyOpts>
): Promise<ArrayBuffer> {
  const cipherText = utils.normalizeToBuf(msg)
  const importedKey = typeof key === 'string' ? await keys.importKey(key, opts) : key
  const alg = opts?.alg || DEFAULT_SYMM_ALG
  const iv = cipherText.slice(0, 16)
  const cipherBytes = cipherText.slice(16)
  const msgBuff = await window.crypto.subtle.decrypt(
    { name: alg,
      length: opts?.length || DEFAULT_SYMM_LEN,
      // AES-CTR uses a counter, AES-GCM/AES-CBC use an initialization vector
      iv: alg === SymmAlg.AES_CTR ? undefined : iv,
      counter: alg === SymmAlg.AES_CTR ? new Uint8Array(iv) : undefined,
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
  return utils.arrBufToBase64(cipherText)
}

export async function decrypt(
  msg: Msg,
  key: SymmKey | string,
  opts?: Partial<SymmKeyOpts>
): Promise<string> {
  const msgBytes = await decryptBytes(msg, key, opts)
  return utils.arrBufToStr(msgBytes, 16)
}


export async function exportKey(key: SymmKey): Promise<string> {
  const raw = await window.crypto.subtle.exportKey('raw', key)
  return utils.arrBufToBase64(raw)
}

export default {
  encryptBytes,
  decryptBytes,
  encrypt,
  decrypt,
  exportKey
}
