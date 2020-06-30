import keys from './keys'
import utils from '../utils'
import { RSA_READ_ALG, RSA_WRITE_ALG, SALT_LENGTH } from '../constants'
import { CharSize, Config, KeyUse, PrivateKey, PublicKey, CipherText } from '../types'
import { defaultConfig } from '../config'

export async function signBytes(
  data: ArrayBuffer,
  privKey: PrivateKey
): Promise<ArrayBuffer> {
  return window.crypto.subtle.sign(
    { name: RSA_WRITE_ALG, saltLength: SALT_LENGTH },
    privKey,
    data
  )
}

export async function signString(
  msg: string,
  privKey: PrivateKey,
  config: Config = defaultConfig
): Promise<string> {
  const sigBytes = await signBytes(
    utils.strToArrBuf(msg, config.charSize),
    privKey
  )

  return utils.arrBufToBase64(sigBytes)
}

export async function verifyBytes(
  data: ArrayBuffer,
  sig: ArrayBuffer,
  pubKey: PublicKey
): Promise<boolean> {
  return window.crypto.subtle.verify(
    { name: RSA_WRITE_ALG, saltLength: SALT_LENGTH },
    pubKey,
    sig,
    data
  )
}

export async function verifyString(
  msg: string,
  signature: string,
  publicKey: string,
  config: Config = defaultConfig
): Promise<boolean> {
  const pubKey = await keys.importPublicKey(publicKey, config.hashAlg, KeyUse.Write)

  return verifyBytes(
    utils.strToArrBuf(msg, config.charSize),
    utils.base64ToArrBuf(signature),
    pubKey
  )
}

export async function encryptBytes(
  data: ArrayBuffer,
  pubKey: PublicKey
): Promise<CipherText> {
  return window.crypto.subtle.encrypt(
    { name: RSA_READ_ALG },
    pubKey,
    data
  )
}

export async function encryptString(
  msg: string,
  publicKey: string,
  config: Config = defaultConfig
): Promise<string> {
  const pubKey = await keys.importPublicKey(publicKey, config.hashAlg, KeyUse.Read)

  const cipherText = await encryptBytes(
    utils.strToArrBuf(msg, config.charSize),
    pubKey
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
  config: Config = defaultConfig
): Promise<string> {
  const msgBytes = await decryptBytes(
    utils.base64ToArrBuf(cipherText),
    privateKey
  )

  return utils.arrBufToStr(msgBytes, config.charSize)
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
