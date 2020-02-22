import IDB from '../idb'
import { RSA_READ_ALG, RSA_WRITE_ALG } from '../constants'

export async function getReadKey(size: RSA_Size, hashAlg: HashAlg, keyName: string): Promise<RsaReadKeyPair> {
  const maybeKey = await IDB.getKey(keyName)
  if(maybeKey){
    return maybeKey
  }
  const keypair = await makeReadKey(size, hashAlg)
  await IDB.putKey(keyName, keypair)
  return keypair
}

export async function getWriteKey(size: RSA_Size, hashAlg: HashAlg, keyName: string): Promise<RsaWriteKeyPair> {
  const maybeKey = await IDB.getKey(keyName)
  if(maybeKey){
    return maybeKey
  }
  const keypair = await makeWriteKey(size, hashAlg)
  await IDB.putKey(keyName, keypair)
  return keypair
}

export async function makeReadKey(size: RSA_Size, hashAlg: HashAlg): Promise<RsaReadKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: RSA_READ_ALG,
      modulusLength: size, 
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {name: hashAlg},
    },
    false,
    ["encrypt", "decrypt"]
  )
}

export async function makeWriteKey(size: RSA_Size, hashAlg: HashAlg): Promise<RsaWriteKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: RSA_WRITE_ALG,
      modulusLength: size,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {name: hashAlg},
    },
    false,
    ["sign", "verify"]
  ) 
}

export default {
  getReadKey,
  getWriteKey,
  makeReadKey,
  makeWriteKey,
}
