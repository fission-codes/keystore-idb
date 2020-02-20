export function structuralClone(obj: any) {
  return new Promise(resolve => {
    const {port1, port2} = new MessageChannel();
    port2.onmessage = ev => resolve(ev.data);
    port1.postMessage(obj);
  });
}

export function arrBuffToStr(buf: ArrayBuffer) {
  const arr = new Uint16Array(buf)
  let result = ''
  for(let i = 0; i < arr.length; i++){
    result += String.fromCharCode(arr[i])
  }
  
  return result
}

export function strToArrBuff(str: string) {
  var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
  var bufView = new Uint16Array(buf);
  for (var i=0, strLen=str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

export default {
  structuralClone,
  arrBuffToStr,
  strToArrBuff
}

