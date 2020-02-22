import keys from './keys'
import operations from './operations'
import config from '../config'
import utils from '../utils'

export async function init(maybeCfg?: PartialConfig): Promise<RSAKeyStore>{
  const cfg = config.normalize({
    ...(maybeCfg || {}),
    type: 'rsa'
  })
  const { rsaSize, hashAlg, readKeyName, writeKeyName } = cfg
  const readKey = await keys.getReadKey(rsaSize, hashAlg, readKeyName)
  const writeKey = await keys.getWriteKey(rsaSize, hashAlg, writeKeyName)
  return new RSAKeyStore(readKey, writeKey, cfg)
}

export class RSAKeyStore implements KeyStore {

  cfg: Config
  readKey: CryptoKeyPair
  writeKey: CryptoKeyPair

  constructor(readKey: CryptoKeyPair, writeKey: CryptoKeyPair, cfg: Config){
    this.cfg = cfg
    this.readKey = readKey
    this.writeKey = writeKey
  }

  async sign(msg: string): Promise<string>{
    const sigBytes = await operations.signBytes(
      utils.strToArrBuf16(msg),
      this.writeKey.privateKey,
    )
    return utils.arrBufToBase64(sigBytes)
  }

  async verify(msg: string, sig: string, publicKey: PublicKey): Promise<boolean> {
    return operations.verifyBytes(
      utils.strToArrBuf16(msg),
      utils.base64ToArrBuf(sig),
      publicKey,
    )
  }

  async encrypt(msg: string, publicKey: PublicKey): Promise<string> {
    const cipherText = await operations.encryptBytes(
      utils.strToArrBuf16(msg),
      publicKey,
    )
    return utils.arrBufToBase64(cipherText)
  }

  async decrypt(cipherText: string): Promise<String> {
    const msgBytes = await operations.decryptBytes(
      utils.base64ToArrBuf(cipherText),
      this.readKey.privateKey,
    )
    return utils.arrBuf16ToStr(msgBytes)
  }

  async publicReadKey(): Promise<string> {
    return operations.getPublicKey(this.readKey)
  }

  async publicWriteKey(): Promise<string> {
    return operations.getPublicKey(this.writeKey)
  }
}

export default {
  init,
  RSAKeyStore,
}
