import KeyStore from './keystore'

async function run() {
  const ALG = 'rsa'
  await KeyStore.clear()
  const ks1 = await KeyStore.init({ type: ALG, readKeyName: 'read-key-1', writeKeyName: 'write-key-1' })
  const ks2 = await KeyStore.init({ type: ALG, readKeyName: 'read-key-2', writeKeyName: 'write-key-2' })

  const msg = "Est culpa culpa deserunt commodo elit labore voluptate nulla commodo cupidatat exercitation. Consectetur esse sit velit ad est proident anim commodo sunt ipsum id ad. Excepteur labore cillum sint non duis laboris magna dolor ullamco est voluptate ea anim. Aute consequat commodo officia et. Reprehenderit ea velit fugiat ullamco enim et commodo non ex. Occaecat elit labore adipisicing ipsum pariatur laborum laboris magna nisi. Officia id voluptate qui magna sunt est enim."
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
}

run()
