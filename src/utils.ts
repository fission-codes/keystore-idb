import * as uint8arrays from 'uint8arrays'
import { CharSize, Msg } from './types'


export function arrBufToStr(buf: ArrayBuffer, charSize: CharSize): string {
  const arr = charSize === 8 ? new Uint8Array(buf) : new Uint16Array(buf)
  return Array.from(arr)
    .map(b => String.fromCharCode(b))
    .join('')
}

export function arrBufToBase64(buf: ArrayBuffer): string {
  return uint8arrays.toString(new Uint8Array(buf), "base64pad")
}

export function strToArrBuf(str: string, charSize: CharSize): ArrayBuffer {
  const view =
    charSize === 8 ? new Uint8Array(str.length) : new Uint16Array(str.length)
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    view[i] = str.charCodeAt(i)
  }
  return view.buffer
}

export function base64ToArrBuf(string: string): ArrayBuffer {
  return uint8arrays.fromString(string, "base64pad").buffer
}

export function publicExponent(): Uint8Array {
  return new Uint8Array([0x01, 0x00, 0x01])
}

export function randomBuf(length: number): ArrayBuffer {
  const arr = new Uint8Array(length)
  globalThis.crypto.getRandomValues(arr)
  return arr.buffer
}

export function joinBufs(fst: ArrayBuffer, snd: ArrayBuffer): ArrayBuffer {
  const view1 = new Uint8Array(fst)
  const view2 = new Uint8Array(snd)
  const joined = new Uint8Array(view1.length + view2.length)
  joined.set(view1)
  joined.set(view2, view1.length)
  return joined.buffer
}

export const normalizeUtf8ToBuf = (msg: Msg): ArrayBuffer => {
  return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B8))
}

export const normalizeUtf16ToBuf = (msg: Msg): ArrayBuffer => {
  return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B16))
}

export const normalizeBase64ToBuf = (msg: Msg): ArrayBuffer => {
  return normalizeToBuf(msg, base64ToArrBuf)
}

export const normalizeUnicodeToBuf = (msg: Msg, charSize: CharSize) => {
  switch (charSize) {
    case 8: return normalizeUtf8ToBuf(msg)
    default: return normalizeUtf16ToBuf(msg)
  }
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
export async function structuralClone(obj: any) {
  return new Promise(resolve => {
    const { port1, port2 } = new MessageChannel()
    port2.onmessage = ev => resolve(ev.data)
    port1.postMessage(obj)
  })
}

export default {
  arrBufToStr,
  arrBufToBase64,
  strToArrBuf,
  base64ToArrBuf,
  publicExponent,
  randomBuf,
  joinBufs,
  normalizeUtf8ToBuf,
  normalizeUtf16ToBuf,
  normalizeBase64ToBuf,
  normalizeToBuf,
  structuralClone
}
