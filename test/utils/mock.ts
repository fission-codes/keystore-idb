import utils from '../../src/utils'

window.atob = require('atob')
window.btoa = require('btoa')

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
  publicKeyHex: 'abcdef1234567890',
  publicKeyBase64: 'q83vEjRWeJA=',
  msgBytes: utils.strToArrBuf("test msg bytes", 16),
  msgStr: "test msg bytes",
  signature: utils.base64ToArrBuf("dGVzdCBzaWduYXR1cmU="),
  signatureStr: "dGVzdCBzaWduYXR1cmU=",
  cipherText: utils.base64ToArrBuf("dGVzdCBlbmNyeXB0ZWQgYnl0ZXM="),
  cipherTextStr: "dGVzdCBlbmNyeXB0ZWQgYnl0ZXM="
}
/* eslint-enable @typescript-eslint/no-explicit-any */
