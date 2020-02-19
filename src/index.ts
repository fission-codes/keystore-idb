import * as idb from 'idb'
import Store from './store'

const DEFAULT_EC_CURVE = 'P-256'
const DEFAULT_SYMM_ALG = 'AES-CTR'
const READ_KEY = 'ecdh-key'
const WRITE_KEY = 'ecdsa-key'

async function encrypt(msg: string, publicKey: CryptoKey) {
  const { privateKey } = await getReadKey()
  const cipherKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: DEFAULT_SYMM_ALG, length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
  // window.crypto.subtle.encrypt(
  //   { name: DEFAULT_SYMM_ALG,
  //     counter: new Uint8Array(8),
  //     length: 128
  //   },
  //   cipherKey,
  //   msg
  // )
  // console.log(cipherKey)
}

async function getPublicReadKey() {
  const keypair = await getReadKey()
  const buffer = await crypto.subtle.exportKey("raw", keypair.publicKey)
  return buffer
}

async function getReadKey() {
  let keypair = await Store.getKey(READ_KEY)
  if(!keypair) {
    console.log('creating read key')
    keypair = await makeReadKey()
    await Store.putKey(READ_KEY, keypair)
  }
  return keypair
}

async function getWriteKey() {
  let keypair = await Store.getKey(WRITE_KEY)
  if(!keypair) {
    console.log('creating write key')
    keypair = await makeWriteKey()
    await Store.putKey(WRITE_KEY, keypair)
  }
  return keypair
}

async function makeReadKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: DEFAULT_EC_CURVE },
    false, 
    ['deriveKey', 'deriveBits']
  ) 
}

async function makeWriteKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: DEFAULT_EC_CURVE },
    false, 
    ['sign', 'verify']
  ) 
}

async function makeRSAKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
        name: "RSA-OAEP",
        modulusLength: 2048, //can be 1024, 2048, or 4096
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    false, //whether the key is extractable (i.e. can be used in exportKey)
    ["encrypt", "decrypt"] //must be ["encrypt", "decrypt"] or ["wrapKey", "unwrapKey"]
  ) 
}

function structuralClone(obj: any) {
  return new Promise(resolve => {
    const {port1, port2} = new MessageChannel();
    port2.onmessage = ev => resolve(ev.data);
    port1.postMessage(obj);
  });
}

function arrbuffToString(arr: ArrayBuffer) {
  const view = new Uint8Array(arr)
  let result = ''
  view.forEach(x => {
    result += x.toString(16)
  })
  console.log(result)
  return result
}

async function run() {
}

run()


export const test = true
