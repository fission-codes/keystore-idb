import utils from '../../src/utils'

window.atob = require('atob')
window.btoa = require('btoa')

const arr = new Uint8Array([1,2,3,4,1,2,3,4,1,2,3,4,1,2,3,4]) 
/* eslint-disable @typescript-eslint/no-explicit-any */
export const mock = {
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
  symmKey: { type: 'symm' } as any,
  iv: arr.buffer,
  iv2: new Uint8Array([9,8,7,6,9,8,7,6,9,8,7,6,9,8,7,6]),
  publicKeyBase64: 'q83vEjRWeJA=',
  msgStr: "test msg bytes",
  msgBytes: utils.strToArrBuf("test msg bytes", 16),
  msgBytesWithIV: utils.joinBufs(arr.buffer, utils.strToArrBuf("test msg bytes", 16)),
  signatureStr: "dGVzdCBzaWduYXR1cmU=",
  signature: utils.base64ToArrBuf("dGVzdCBzaWduYXR1cmU="),
  cipherTextStr: "dGVzdCBlbmNyeXB0ZWQgYnl0ZXM=",
  cipherText: utils.base64ToArrBuf("dGVzdCBlbmNyeXB0ZWQgYnl0ZXM="),
  cipherTextWithIV: utils.joinBufs(arr.buffer, utils.base64ToArrBuf("dGVzdCBlbmNyeXB0ZWQgYnl0ZXM=")),
}
/* eslint-enable @typescript-eslint/no-explicit-any */
