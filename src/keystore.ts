import ecc from './ecc'
import config from './config'
import utils from './utils'

export async function init(maybeCfg?: PartialConfig): Promise<KeyStore>{
  const cfg = await config.normalize(maybeCfg)
  const { curve, readKeyName, writeKeyName } = cfg
  const readKey = await ecc.getReadKey(curve, readKeyName)
  const writeKey = await ecc.getWriteKey(curve, writeKeyName)
  return new KeyStore(cfg, readKey, writeKey)
}

export class KeyStore {

  cfg: Config
  readKey: CryptoKeyPair
  writeKey: CryptoKeyPair

  constructor(cfg: Config, readKey: CryptoKeyPair, writeKey: CryptoKeyPair){
    this.cfg = cfg
    this.readKey = readKey
    this.writeKey = writeKey
  }

  async sign(msg: string): Promise<string>{
    const sigBytes = await ecc.signBytes(
      utils.strToArrBuf(msg),
      this.writeKey.privateKey,
      this.cfg.hashAlg
    )
    return utils.arrBufToHex(sigBytes)
  }

  async verify(msg: string, sig: string, publicKey: PublicKey): Promise<boolean> {
    return ecc.verifyBytes(
      utils.strToArrBuf(msg),
      utils.hexToArrBuf(sig),
      publicKey,
      this.cfg.hashAlg
    )
  }

  async encrypt(msg: string, publicKey: PublicKey): Promise<string> {
    const cipherText = await ecc.encryptBytes(
      utils.strToArrBuf(msg),
      this.readKey.privateKey,
      publicKey,
      this.cfg.symmAlg
    )
    return utils.arrBufToHex(cipherText)
  }

  async decrypt(cipherText: string, publicKey: PublicKey): Promise<String> {
    const msgBytes = await ecc.decryptBytes(
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

export default init
