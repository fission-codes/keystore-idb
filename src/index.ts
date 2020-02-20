import utils from './utils'
import operations from './operations'
import keys from './keys'

async function run() {
  const msg = 'blahblahblha'
  const msgBytes = utils.strToArrBuf(msg)
  const { publicKey } = await keys.getWriteKey()

  const sig = await operations.sign(msg)
  const verified = await operations.verify(msg, sig, publicKey)

  const sigBytes = await operations.signBytes(msgBytes)
  const verifiedBytes = await operations.verifyBytes(msgBytes, sigBytes, publicKey)
  console.log(sig)
  console.log(verified)
  console.log(verifiedBytes)
}

run()

export * from './keys'
export * from './operations'
export * from './utils'
