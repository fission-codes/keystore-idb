import { webcrypto } from 'one-webcrypto'
import * as uint8arrays from 'uint8arrays'
import { Msg } from './types.js'


export function publicExponent(): Uint8Array {
  return new Uint8Array([0x01, 0x00, 0x01])
}

export function randomBuf(length: number): Uint8Array {
  return webcrypto.getRandomValues(new Uint8Array(length))
}

export const normalizeAssumingBase64 = (msg: Msg): Uint8Array => {
  return normalizeToBuf(msg, base64 => uint8arrays.fromString(base64, "base64pad"))
}

export const normalizeAssumingUtf8 = (msg: Msg): Uint8Array => {
  return normalizeToBuf(msg, str => uint8arrays.fromString(str, "utf8"))
}

const normalizeToBuf = (msg: Msg, strConv: (str: string) => Uint8Array): Uint8Array => {
  if (typeof msg === 'string') {
    return strConv(msg)
    // this is the best runtime check I could find for ArrayBuffer/Uint8Array
  } else if (typeof msg === 'object' && msg.byteLength !== undefined) {
    return new Uint8Array(msg)
  } else {
    throw new Error("Improper value. Must be a Uint8Array, string or ArrayBuffer")
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
