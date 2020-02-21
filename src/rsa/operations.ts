import { RSA_READ_ALG, RSA_WRITE_ALG, SALT_LENGTH } from '../constants'

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
  return crypto.subtle.encrypt(
    { name: RSA_READ_ALG },
    publicKey,
    data
  )
}

export async function decryptBytes(cipherText: CipherText, privateKey: PrivateKey): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    { name: RSA_READ_ALG },
    privateKey,
    cipherText
  )
}

export default {
  signBytes,
  verifyBytes,
  encryptBytes,
  decryptBytes,
}
