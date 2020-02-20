import Store from './store'
import utils from './utils'

const DEFAULT_EC_CURVE = 'P-256'
const DEFAULT_SYMM_ALG = 'AES-CTR'
const READ_KEY = 'ecdh-key'
const WRITE_KEY = 'ecdsa-key'

type CipherText = ArrayBuffer
type PublicKey = CryptoKey
type SymmKey = CryptoKey
type ReadKeyPair = CryptoKeyPair
type WriteKeyPair = CryptoKeyPair

async function getSharedKey(publicKey: PublicKey): Promise<SymmKey> {
  const { privateKey } = await getReadKey()
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: DEFAULT_SYMM_ALG, length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

async function encrypt(msg: string, publicKey: PublicKey): Promise<CipherText> {
  const cipherKey = await getSharedKey(publicKey)
  return crypto.subtle.encrypt(
    { name: DEFAULT_SYMM_ALG,
      counter: new Uint8Array(16),
      length: 128
    },
    cipherKey,
    utils.strToArrBuff(msg)
  )
}

async function decrypt(cipherText: CipherText, publicKey: CryptoKey): Promise<string> {
  const cipherKey = await getSharedKey(publicKey)
  const msgBuff = await crypto.subtle.encrypt(
    { name: DEFAULT_SYMM_ALG,
      counter: new Uint8Array(16),
      length: 128
    },
    cipherKey,
    cipherText
  )
  return utils.arrBuffToStr(msgBuff)
}

async function getPublicReadKey(): Promise<string> {
  const keypair = await getReadKey()
  const buffer = await crypto.subtle.exportKey("raw", keypair.publicKey)
  return utils.arrBuffToStr(buffer)
}

async function getReadKey(): Promise<ReadKeyPair> {
  let keypair = await Store.getKey(READ_KEY)
  if(!keypair) {
    console.log('creating read key')
    keypair = await makeReadKey()
    await Store.putKey(READ_KEY, keypair)
  }
  return keypair
}

async function getWriteKey(): Promise<WriteKeyPair> {
  let keypair = await Store.getKey(WRITE_KEY)
  if(!keypair) {
    console.log('creating write key')
    keypair = await makeWriteKey()
    await Store.putKey(WRITE_KEY, keypair)
  }
  return keypair
}

async function makeReadKey(): Promise<ReadKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: DEFAULT_EC_CURVE },
    false, 
    ['deriveKey', 'deriveBits']
  ) 
}

async function makeWriteKey(): Promise<WriteKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: DEFAULT_EC_CURVE },
    false, 
    ['sign', 'verify']
  ) 
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

async function run() {
  // const otherKey = await makeReadKey()
  // const orig = 'blahblahlb'
  // const cipher = await encrypt(orig, otherKey.publicKey)
  // const msg = await decrypt(cipher, otherKey.publicKey)
  const hex = '1234567890abcdef2340980abc098d'
  const ab = utils.hexToArrBuff(hex)
  const str = utils.arrBuffToHex(ab)
  console.log(hex)
  console.log(ab)
  console.log(str)
  // console.log(orig)
  // console.log(cipher)
  // console.log(msg)
}

run()


export const test = true
