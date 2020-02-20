export function structuralClone(obj: any) {
  return new Promise(resolve => {
    const {port1, port2} = new MessageChannel();
    port2.onmessage = ev => resolve(ev.data);
    port1.postMessage(obj);
  });
}

export function arrBufToStr(buf: ArrayBuffer): string {
  return Array
    .from(new Uint16Array(buf))
    .map(b => String.fromCharCode(b))
    .join("")
}

export function arrBufToHex(buf: ArrayBuffer): string {
  return Array
    .from (new Uint8Array(buf))
    .map (b => b.toString (16).padStart (2, "0"))
    .join ("");
}

export function strToArrBuf(str: string): ArrayBuffer {
  const view = new Uint16Array(2 * str.length)
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

export default {
  structuralClone,
  arrBufToStr,
  arrBufToHex,
  strToArrBuf,
  hexToArrBuf,
}
