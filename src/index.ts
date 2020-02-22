import KeyStore from './keystore'

async function run() {
  const ALG = 'rsa'
  await KeyStore.clear()
  const ks1 = await KeyStore.init({ type: ALG, readKeyName: 'read-key-1', writeKeyName: 'write-key-1' })
  const ks2 = await KeyStore.init({ type: ALG, readKeyName: 'read-key-2', writeKeyName: 'write-key-2' })

  const msg = "Incididunt id ullamco et do."
  const readKey1 = ks1.readKey
  const readKey2 = ks2.readKey
  const writeKey1 = ks1.writeKey

  const sig = await ks1.sign(msg)
  const valid = await ks2.verify(msg, sig, writeKey1.publicKey)
  console.log('sig: ', sig)
  console.log('valid: ', valid)

  const cipher = await ks1.encrypt(msg, readKey2.publicKey)
  const decipher = await ks2.decrypt(cipher, readKey1.publicKey)
  console.log('cipher: ', cipher)
  console.log('decipher: ', decipher)

  // read keys are write keys are separate because of the Web Crypto API
  const readKey = await ks1.publicReadKey()
  const writeKey = await ks1.publicWriteKey()
  console.log('readKey: ', readKey)
  console.log('writeKey: ', writeKey)
}

run()
