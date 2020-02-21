import IDB from '../idb'
import utils from '../utils'
import { RSA_READ_KEY, RSA_WRITE_KEY, RSA_KEY_SIZE, DEFAULT_HASH_ALG } from '../constants'

export async function getReadKey(): Promise<RsaReadKeyPair> {
  let keypair = await IDB.getKey(RSA_READ_KEY)
  if(!keypair) {
    console.log('creating read key')
    keypair = await makeReadKey()
    await IDB.putKey(RSA_READ_KEY, keypair)
  }
  return keypair
}

export async function getWriteKey(): Promise<RsaWriteKeyPair> {
  let keypair = await IDB.getKey(RSA_WRITE_KEY)
  if(!keypair) {
    console.log('creating write key')
    keypair = await makeWriteKey()
    await IDB.putKey(RSA_WRITE_KEY, keypair)
  }
  return keypair
}

export async function makeReadKey(): Promise<RsaWriteKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: RSA_WRITE_KEY,
      modulusLength: RSA_KEY_SIZE,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {name: DEFAULT_HASH_ALG},
    },
    false,
    ["encrypt", "decrypt"]
  ) 
}

export async function makeWriteKey(): Promise<RsaWriteKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: RSA_READ_KEY,
      modulusLength: RSA_KEY_SIZE,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {name: DEFAULT_HASH_ALG},
    },
    false,
    ["sign", "verify"]
  ) 
}

export async function getPublicReadKey(): Promise<string> {
  const pubkey = await getPublicReadKeyBytes()
  return utils.arrBufToHex(pubkey)
}

export async function getPublicReadKeyBytes(): Promise<ArrayBuffer> {
  const keypair = await getReadKey()
  return keyPairToPublic(keypair)
}

export async function getPublicWriteKey(): Promise<string> {
  const pubkey = await getPublicWriteKeyBytes()
  return utils.arrBufToHex(pubkey)
}

export async function getPublicWriteKeyBytes(): Promise<ArrayBuffer> {
  const keypair = await getWriteKey()
  return keyPairToPublic(keypair)
}

async function keyPairToPublic(keypair: CryptoKeyPair): Promise<ArrayBuffer> {
  return crypto.subtle.exportKey("raw", keypair.publicKey)
}

export default {
  getReadKey,
  getWriteKey,
  makeReadKey,
  makeWriteKey,
  getPublicReadKey,
  getPublicReadKeyBytes,
  getPublicWriteKey,
  getPublicWriteKeyBytes,
}
