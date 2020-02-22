import keys from './keys'
import operations from './operations'
import config from '../config'
import utils from '../utils'

export async function init(maybeCfg?: PartialConfig): Promise<ECCKeyStore>{
  const cfg = config.normalize({
    ...(maybeCfg || {}),
    type: 'ecc'
  })
  const { curve, readKeyName, writeKeyName } = cfg
  const readKey = await keys.getReadKey(curve, readKeyName)
  const writeKey = await keys.getWriteKey(curve, writeKeyName)
  return new ECCKeyStore(readKey, writeKey, cfg)
}

export class ECCKeyStore implements KeyStore {

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
      this.cfg.hashAlg
    )
    return utils.arrBufToBase64(sigBytes)
  }

  async verify(msg: string, sig: string, publicKey: PublicKey): Promise<boolean> {
    return operations.verifyBytes(
      utils.strToArrBuf16(msg),
      utils.base64ToArrBuf(sig),
      publicKey,
      this.cfg.hashAlg
    )
  }

  async encrypt(msg: string, publicKey: PublicKey): Promise<string> {
    const cipherText = await operations.encryptBytes(
      utils.strToArrBuf16(msg),
      this.readKey.privateKey,
      publicKey,
      this.cfg.symmAlg
    )
    return utils.arrBufToBase64(cipherText)
  }

  async decrypt(cipherText: string, publicKey: PublicKey): Promise<String> {
    const msgBytes = await operations.decryptBytes(
      utils.base64ToArrBuf(cipherText),
      this.readKey.privateKey,
      publicKey,
      this.cfg.symmAlg
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
  ECCKeyStore,
}
