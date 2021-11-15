import { webcrypto } from 'one-webcrypto'
import * as uint8arrays from 'uint8arrays'
import { Msg } from './types.js'


function strToArrBuf(str: string, charSize: number): ArrayBuffer {
  const view =
    charSize === 8 ? new Uint8Array(str.length) : new Uint16Array(str.length)
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    view[i] = str.charCodeAt(i)
  }
  return view.buffer
}

export function publicExponent(): Uint8Array {
  return new Uint8Array([0x01, 0x00, 0x01])
}

export function randomBuf(length: number): ArrayBuffer {
  const arr = new Uint8Array(length)
  webcrypto.getRandomValues(arr)
  return arr.buffer
}

export const normalizeUtf8ToBuf = (msg: Msg): ArrayBuffer => {
  return normalizeToBuf(msg, (str) => strToArrBuf(str, 8))
}

export const normalizeUtf16ToBuf = (msg: Msg): ArrayBuffer => {
  return normalizeToBuf(msg, (str) => strToArrBuf(str, 16))
}

export const normalizeBase64ToBuf = (msg: Msg): ArrayBuffer => {
  return normalizeToBuf(msg, base64 => uint8arrays.fromString(base64, "base64pad").buffer)
}

// TODO: Rename.
export const normalizeUnicodeToBuf = (msg: Msg): ArrayBuffer => {
  if (typeof msg === "string") {
    return uint8arrays.fromString(msg, "utf8").buffer
  }
  if (msg instanceof Uint8Array) {
    return msg.buffer
  }
  return msg
}

export const normalizeToBuf = (msg: Msg, strConv: (str: string) => ArrayBuffer): ArrayBuffer => {
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
  normalizeUtf8ToBuf,
  normalizeUtf16ToBuf,
  normalizeBase64ToBuf,
  normalizeUnicodeToBuf,
  normalizeToBuf,
  structuralClone
}
