import IDB from './idb'
import utils from './utils'
import { READ_KEY, WRITE_KEY, DEFAULT_EC_CURVE } from './constants'

export async function getReadKey(): Promise<ReadKeyPair> {
  let keypair = await IDB.getKey(READ_KEY)
  if(!keypair) {
    console.log('creating read key')
    keypair = await makeReadKey()
    await IDB.putKey(READ_KEY, keypair)
  }
  return keypair
}

export async function getWriteKey(): Promise<WriteKeyPair> {
  let keypair = await IDB.getKey(WRITE_KEY)
  if(!keypair) {
    console.log('creating write key')
    keypair = await makeWriteKey()
    await IDB.putKey(WRITE_KEY, keypair)
  }
  return keypair
}

export async function makeReadKey(): Promise<ReadKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: DEFAULT_EC_CURVE },
    false, 
    ['deriveKey', 'deriveBits']
  ) 
}

export async function makeWriteKey(): Promise<WriteKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: DEFAULT_EC_CURVE },
    false, 
    ['sign', 'verify']
  ) 
}

export async function getPublicReadKey(): Promise<string> {
  const keypair = await getReadKey()
  return keyPairToPublic(keypair)
}

export async function getPublicWriteKey(): Promise<string> {
  const keypair = await getWriteKey()
  return keyPairToPublic(keypair)
}

async function keyPairToPublic(keypair: CryptoKeyPair): Promise<string> {
  const buffer = await crypto.subtle.exportKey("raw", keypair.publicKey)
  return utils.arrBufToHex(buffer)
}

// async function makeRSAKey(): Promise<CryptoKeyPair> {
//   return crypto.subtle.generateKey(
//     {
//         name: "RSA-OAEP",
//         modulusLength: 2048, //can be 1024, 2048, or 4096
//         publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
//         hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
//     },
//     false, //whether the key is extractable (i.e. can be used in exportKey)
//     ["encrypt", "decrypt"] //must be ["encrypt", "decrypt"] or ["wrapKey", "unwrapKey"]
//   ) 
// }

export default {
  getReadKey,
  getWriteKey,
  makeReadKey,
  makeWriteKey,
  getPublicReadKey,
  getPublicWriteKey,
}
