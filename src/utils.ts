import { CharSize } from './types'

export function arrBufToStr(buf: ArrayBuffer, charSize: CharSize): string {
  const arr = charSize === 8 ? new Uint8Array(buf) : new Uint16Array(buf)
  return Array.from(arr)
    .map(b => String.fromCharCode(b))
    .join('')
}

export function arrBufToBase64(buf: ArrayBuffer): string {
  const str = arrBufToStr(buf, 8)
  return window.btoa(str)
}

export function strToArrBuf(str: string, charSize: CharSize): ArrayBuffer {
  const view =
    charSize === 8 ? new Uint8Array(str.length) : new Uint16Array(str.length)
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    view[i] = str.charCodeAt(i)
  }
  return view.buffer
}

export function base64ToArrBuf(base64: string): ArrayBuffer {
  const str = window.atob(base64)
  return strToArrBuf(str, 8)
}

export function publicExponent(): Uint8Array {
  return new Uint8Array([0x01, 0x00, 0x01])
}

export function randomBuf(length: number): ArrayBuffer {
  const arr = new Uint8Array(length)
  window.crypto.getRandomValues(arr)
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
  structuralClone
}
