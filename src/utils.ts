import { webcrypto } from 'one-webcrypto'
import * as uint8arrays from 'uint8arrays'
import { Msg } from './types.js'


export function publicExponent(): Uint8Array {
  return new Uint8Array([0x01, 0x00, 0x01])
}

export function randomBuf(length: number): ArrayBuffer {
  const arr = new Uint8Array(length)
  webcrypto.getRandomValues(arr)
  return arr.buffer
}

export const normalizeAssumingBase64 = (msg: Msg): ArrayBuffer => {
  return normalizeToBuf(msg, base64 => uint8arrays.fromString(base64, "base64pad").buffer)
}

export const normalizeAssumingUtf8 = (msg: Msg): ArrayBuffer => {
  return normalizeToBuf(msg, str => uint8arrays.fromString(str, "utf8").buffer)
}

const normalizeToBuf = (msg: Msg, strConv: (str: string) => ArrayBuffer): ArrayBuffer => {
  if (typeof msg === 'string') {
    return strConv(msg)
  } else if (typeof msg === 'object' && msg.byteLength !== undefined) {
    // this is the best runtime check I could find for ArrayBuffer/Uint8Array
    const temp = new Uint8Array(msg)
    return temp.buffer
  } else {
    throw new Error("Improper value. Must be a string, ArrayBuffer, Uint8Array")
  }
}

/* istanbul ignore next */
export async function structuralClone<T>(obj: T): Promise<T> {
  return new Promise(resolve => {
    const { port1, port2 } = new MessageChannel()
    port2.onmessage = ev => resolve(ev.data)
    port1.postMessage(obj)
  })
}

export default {
  publicExponent,
  randomBuf,
  normalizeBase64ToBuf: normalizeAssumingBase64,
  normalizeUnicodeToBuf: normalizeAssumingUtf8,
  normalizeToBuf,
  structuralClone
}
