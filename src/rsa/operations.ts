import utils from '../utils'
import { RSA_READ_ALG, RSA_WRITE_ALG, SALT_LENGTH } from '../constants'
import { PrivateKey, PublicKey, CipherText, HashAlg } from '../types'

export async function signBytes(data: ArrayBuffer, privKey: PrivateKey): Promise<ArrayBuffer> {
  return window.crypto.subtle.sign(
    { name: RSA_WRITE_ALG, saltLength: SALT_LENGTH },
    privKey,
    data
  )
}

export async function verifyBytes(data: ArrayBuffer, sig: ArrayBuffer, publicKey: PublicKey): Promise<boolean> {
  return window.crypto.subtle.verify(
    { name: RSA_WRITE_ALG, saltLength: SALT_LENGTH },
    publicKey,
    sig, 
    data 
  )
}

export async function encryptBytes(data: ArrayBuffer, publicKey: PublicKey): Promise<CipherText> {
  return window.crypto.subtle.encrypt(
    { name: RSA_READ_ALG },
    publicKey,
    data
  )
}

export async function decryptBytes(cipherText: CipherText, privateKey: PrivateKey): Promise<ArrayBuffer> {
  return window.crypto.subtle.decrypt(
    { name: RSA_READ_ALG },
    privateKey,
    cipherText
  )
}

export async function getPublicKey(keypair: CryptoKeyPair): Promise<string> {
  const spki = await window.crypto.subtle.exportKey('spki', keypair.publicKey)
  return `-----BEGIN PUBLIC KEY-----\n${utils.arrBufToBase64(spki)}\n-----END PUBLIC KEY-----`
}

export default {
  signBytes,
  verifyBytes,
  encryptBytes,
  decryptBytes,
  getPublicKey,
}
