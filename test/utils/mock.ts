import utils from '../../src/utils'

window.atob = require('atob')
window.btoa = require('btoa')

const iv = (new Uint8Array([1,2,3,4,1,2,3,4,1,2,3,4,1,2,3,4])).buffer
const msgStr = "test msg bytes"
const msgBytes = utils.strToArrBuf(msgStr, 16)
const sigStr = "dGVzdCBzaWduYXR1cmU="
const sigBytes = utils.base64ToArrBuf(sigStr)
const cipherStr = "dGVzdCBlbmNyeXB0ZWQgYnl0ZXM="
const cipherBytes = utils.base64ToArrBuf(cipherStr)
const cipherWithIVBytes = utils.joinBufs(iv, cipherBytes)
const cipherWithIVStr = utils.arrBufToBase64(cipherWithIVBytes)

/* eslint-disable @typescript-eslint/no-explicit-any */
export const mock = {
  idbStore: {
    type: 'fake-store'
  } as any,
  keys: {
    publicKey: { type: 'pub' } as any,
    privateKey: { type: 'priv' } as any
  } as any,
  writeKeys: {
    publicKey: { type: 'write-pub' } as any,
    privateKey: { type: 'write-priv' } as any
  } as any,
  encryptForKey: {
    publicKey: { type: 'encrypt-pub' } as any,
    privateKey: { type: 'encrypt-priv' } as any 
  } as any,
  symmKey: { type: 'symm', algorithm: 'AES-CTR' } as any,
  symmKeyName: 'symm-key',
  keyBase64: 'q83vEjRWeJA=',
  iv,
  msgStr,
  msgBytes,
  sigStr,
  sigBytes,
  cipherStr,
  cipherBytes,
  cipherWithIVStr,
  cipherWithIVBytes,
}

export default mock
/* eslint-enable @typescript-eslint/no-explicit-any */
