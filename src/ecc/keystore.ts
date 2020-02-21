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
      utils.strToArrBuf(msg),
      this.writeKey.privateKey,
      this.cfg.hashAlg
    )
    return utils.arrBufToHex(sigBytes)
  }

  async verify(msg: string, sig: string, publicKey: PublicKey): Promise<boolean> {
    return operations.verifyBytes(
      utils.strToArrBuf(msg),
      utils.hexToArrBuf(sig),
      publicKey,
      this.cfg.hashAlg
    )
  }

  async encrypt(msg: string, publicKey: PublicKey): Promise<string> {
    const cipherText = await operations.encryptBytes(
      utils.strToArrBuf(msg),
      this.readKey.privateKey,
      publicKey,
      this.cfg.symmAlg
    )
    return utils.arrBufToHex(cipherText)
  }

  async decrypt(cipherText: string, publicKey: PublicKey): Promise<String> {
    const msgBytes = await operations.decryptBytes(
      utils.hexToArrBuf(cipherText),
      this.readKey.privateKey,
      publicKey,
      this.cfg.symmAlg
    )
    return utils.arrBufToStr(msgBytes)
  }

  async publicReadKey(): Promise<string> {
    return utils.getPublicKey(this.readKey)
  }

  async publicWriteKey(): Promise<string> {
    return utils.getPublicKey(this.writeKey)
  }
}

export default {
  init,
  ECCKeyStore,
}
