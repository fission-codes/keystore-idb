export function arrBufToStr(buf: ArrayBuffer, charSize: CharSize): string {
  const arr = charSize === 8 ? new Uint8Array(buf) : new Uint16Array(buf)
  return Array
    .from(arr)
    .map(b => String.fromCharCode(b))
    .join("")
}

export function arrBufToHex(buf: ArrayBuffer): string {
  return Array
    .from (new Uint8Array(buf))
    .map (b => b.toString (16).padStart (2, "0"))
    .join("");
}

export function arrBufToBase64(buf: ArrayBuffer): string {
  const str = arrBufToStr(buf, 8)
  return window.btoa(str)
}

export function strToArrBuf(str: string, charSize: CharSize): ArrayBuffer {
  const view = charSize === 8 ? new Uint8Array(str.length) : new Uint16Array(str.length)
  for(let i=0, strLen=str.length; i < strLen; i++){
    view[i] = str.charCodeAt(i)
  }
  return view.buffer
}

export function hexToArrBuf(hex: string): ArrayBuffer {
  const view = new Uint8Array(hex.length / 2)
  for (let i=0, hexLen=hex.length; i < hexLen; i += 2) {
    view[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return view.buffer
}

export function base64ToArrBuf(base64: string): ArrayBuffer {
  const str = window.atob(base64)
  return strToArrBuf(str, 8)
}

export async function structuralClone(obj: any) {
  return new Promise(resolve => {
    const {port1, port2} = new MessageChannel();
    port2.onmessage = ev => resolve(ev.data);
    port1.postMessage(obj);
  });
}

export default {
  arrBufToStr,
  arrBufToHex,
  arrBufToBase64,
  strToArrBuf,
  hexToArrBuf,
  base64ToArrBuf,
  structuralClone,
}
