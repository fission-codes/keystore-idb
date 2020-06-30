import keys from './keys'
import utils from '../utils'
import { RSA_READ_ALG, RSA_WRITE_ALG, SALT_LENGTH } from '../constants'
import { CharSize, Config, KeyUse, PrivateKey, PublicKey, CipherText } from '../types'
import { defaultConfig } from '../config'

export async function signBytes(
  data: ArrayBuffer,
  privateKey: PrivateKey
): Promise<ArrayBuffer> {
  return window.crypto.subtle.sign(
    { name: RSA_WRITE_ALG, saltLength: SALT_LENGTH },
    privateKey,
    data
  )
}

export async function signString(
  msg: string,
  privateKey: PrivateKey,
  cfg: Config = defaultConfig
): Promise<string> {
  const sigBytes = await signBytes(
    utils.strToArrBuf(msg, cfg.charSize),
    privateKey
  )

  return utils.arrBufToBase64(sigBytes)
}

export async function verifyBytes(
  data: ArrayBuffer,
  sig: ArrayBuffer,
  publicKey: PublicKey
): Promise<boolean> {
  return window.crypto.subtle.verify(
    { name: RSA_WRITE_ALG, saltLength: SALT_LENGTH },
    publicKey,
    sig,
    data
  )
}

export async function verifyString(
  msg: string,
  sig: string,
  publicKey64: string,
  cfg: Config = defaultConfig
): Promise<boolean> {
  const publicKey = await keys.importPublicKey(publicKey64, cfg.hashAlg, KeyUse.Write)

  return verifyBytes(
    utils.strToArrBuf(msg, cfg.charSize),
    utils.base64ToArrBuf(sig),
    publicKey
  )
}

export async function encryptBytes(
  data: ArrayBuffer,
  publicKey: PublicKey
): Promise<CipherText> {
  return window.crypto.subtle.encrypt(
    { name: RSA_READ_ALG },
    publicKey,
    data
  )
}

export async function encryptString(
  msg: string,
  publicKey64: string,
  cfg: Config = defaultConfig
): Promise<string> {
  const publicKey = await keys.importPublicKey(publicKey64, cfg.hashAlg, KeyUse.Read)
  const cipherText = await encryptBytes(
    utils.strToArrBuf(msg, cfg.charSize),
    publicKey
  )

  return utils.arrBufToBase64(cipherText)
}

export async function decryptBytes(
  cipherText: CipherText,
  privateKey: PrivateKey
): Promise<ArrayBuffer> {
  return window.crypto.subtle.decrypt(
    { name: RSA_READ_ALG },
    privateKey,
    cipherText
  )
}

export async function decryptString(
  cipherText: string,
  privateKey: PrivateKey,
  cfg: Config = defaultConfig
): Promise<string> {
  const msgBytes = await decryptBytes(
    utils.base64ToArrBuf(cipherText),
    privateKey
  )

  return utils.arrBufToStr(msgBytes, cfg.charSize)
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
