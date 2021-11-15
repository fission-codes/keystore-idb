import * as uint8arrays from "uint8arrays"

const iv = new Uint8Array([1,2,3,4,1,2,3,4,1,2,3,4,1,2,3,4])
const msgStr = "test msg bytes"
const msgBytes = uint8arrays.fromString(msgStr)
const sigStr = "dGVzdCBzaWduYXR1cmU="
const sigBytes = uint8arrays.fromString(sigStr, "base64pad")
const cipherStr = "dGVzdCBlbmNyeXB0ZWQgYnl0ZXM="
const cipherBytes = uint8arrays.fromString(cipherStr, "base64pad")
const cipherWithIVBytes = uint8arrays.concat([iv, cipherBytes])
const cipherWithIVStr = uint8arrays.toString(cipherWithIVBytes, "base64pad")

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
