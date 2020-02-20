type ByteArray = Uint8Array | Uint16Array

export function structuralClone(obj: any) {
  return new Promise(resolve => {
    const {port1, port2} = new MessageChannel();
    port2.onmessage = ev => resolve(ev.data);
    port1.postMessage(obj);
  });
}

export function arrBufToStr(buf: ArrayBuffer) {
  return arrToStr(new Uint16Array(buf))
}

export function strToArrBuf(str: string) {
  return strToArr(str, 2)
}

export function arrBufToHex(buf: ArrayBuffer) {
  return arrToStr(new Uint8Array(buf))
}

export function hexToArrBuf(hex: string) {
  return strToArr(hex, 1)
}

function arrToStr(arr: ByteArray) {
  let result = ''
  for(let i = 0; i < arr.length; i++){
    result += String.fromCharCode(arr[i])
  }
  return result
}

function strToArr(str: string, bytesPerChar: 1 | 2){
  const buf = new ArrayBuffer(str.length * bytesPerChar)
  let bufView
  if(bytesPerChar === 1){
    bufView = new Uint8Array(buf)
  }else if (bytesPerChar === 2) {
    bufView = new Uint16Array(buf)
  }else {
    throw new Error("String converstion not supported")
  }
  for (var i=0, strLen=str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

export default {
  structuralClone,
  arrBufToStr,
  strToArrBuf,
  arrBufToHex,
  hexToArrBuf,
}
