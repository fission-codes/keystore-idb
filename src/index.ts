import utils from './utils'

async function run() {
  // const otherKey = await makeReadKey()
  // const orig = 'blahblahlb'
  // const cipher = await encrypt(orig, otherKey.publicKey)
  // const msg = await decrypt(cipher, otherKey.publicKey)
  const hex = '1234567890abcdef2340980abc098d'
  const ab = utils.hexToArrBuf(hex)
  const str = utils.arrBufToHex(ab)
  console.log(hex)
  console.log(ab)
  console.log(str)
  // console.log(orig)
  // console.log(cipher)
  // console.log(msg)
}

run()

export * from './keys'
export * from './operations'
export * from './utils'
