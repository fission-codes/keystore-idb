import aes from '../aes'
import keys from './keys'
import utils from '../utils'
import { ECC_READ_ALG, ECC_WRITE_ALG, DEFAULT_SYMM_ALG, DEFAULT_SYMM_LEN } from '../constants'
import { Config, PrivateKey, PublicKey, HashAlg, KeyUse, SymmKey, SymmKeyOpts, CipherText } from '../types'
import config, { defaultConfig } from '../config'

export async function signBytes(
  data: ArrayBuffer,
  privateKey: PrivateKey,
  hashAlg: HashAlg
): Promise<ArrayBuffer> {
  return window.crypto.subtle.sign(
    { name: ECC_WRITE_ALG, hash: {name: hashAlg }},
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
    privateKey,
    cfg.hashAlg
  )

  return utils.arrBufToBase64(sigBytes)
}

export async function verifyBytes(
  data: ArrayBuffer,
  sig: ArrayBuffer,
  publicKey: PublicKey,
  hashAlg: HashAlg
): Promise<boolean> {
  return window.crypto.subtle.verify(
    { name: ECC_WRITE_ALG, hash: {name: hashAlg }},
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
  const publicKey = await keys.importPublicKey(publicKey64, cfg.curve, KeyUse.Write)

  return verifyBytes(
    utils.strToArrBuf(msg, cfg.charSize),
    utils.base64ToArrBuf(sig),
    publicKey,
    cfg.hashAlg
  )
}

export async function encryptBytes(
  data: ArrayBuffer,
  privateKey: PrivateKey,
  publicKey: PublicKey,
  opts?: Partial<SymmKeyOpts>
): Promise<CipherText> {
  const cipherKey = await getSharedKey(privateKey, publicKey, opts)
  return aes.encryptBytes(data, cipherKey, opts)
}

export async function encryptString(
  msg: string,
  privateKey: PrivateKey,
  publicKey64: string,
  cfg: Config = defaultConfig
): Promise<string> {
  const publicKey = await keys.importPublicKey(publicKey64, cfg.curve, KeyUse.Read)
  const cipherText = await encryptBytes(
    utils.strToArrBuf(msg, cfg.charSize),
    privateKey,
    publicKey,
    config.symmKeyOpts(cfg)
  )

  return utils.arrBufToBase64(cipherText)
}

export async function decryptBytes(
  cipherText: CipherText,
  privateKey: PrivateKey,
  publicKey: PublicKey,
  opts?: Partial<SymmKeyOpts>
): Promise<ArrayBuffer> {
  const cipherKey = await getSharedKey(privateKey, publicKey, opts)
  return aes.decryptBytes(cipherText, cipherKey, opts)
}

export async function decryptString(
  cipherText: string,
  privateKey: PrivateKey,
  publicKey64: string,
  cfg: Config = defaultConfig
): Promise<string> {
  const publicKey = await keys.importPublicKey(publicKey64, cfg.curve, KeyUse.Read)
  const msgBytes = await decryptBytes(
    utils.base64ToArrBuf(cipherText),
    privateKey,
    publicKey,
    config.symmKeyOpts(cfg)
  )

  return utils.arrBufToStr(msgBytes, cfg.charSize)
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
  signBytes,
  signString,
  verifyBytes,
  verifyString,
  encryptBytes,
  encryptString,
  decryptBytes,
  decryptString,
  getPublicKey,
  getSharedKey
}
