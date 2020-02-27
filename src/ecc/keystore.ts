import keys from './keys'
import operations from './operations'
import config from '../config'
import utils from '../utils'
import { KeyStore, PartialConfig, Config, KeyUse, CharSize, CryptoSystem } from '../types'

export async function init(maybeCfg?: PartialConfig): Promise<ECCKeyStore> {
  const cfg = config.normalize({
    ...(maybeCfg || {}),
    type: CryptoSystem.ECC
  })
  const { curve, readKeyName, writeKeyName } = cfg
  const readKey = await keys.getKey(curve, readKeyName, KeyUse.Read)
  const writeKey = await keys.getKey(curve, writeKeyName, KeyUse.Write)
  return new ECCKeyStore(readKey, writeKey, cfg)
}

export class ECCKeyStore implements KeyStore {
  cfg: Config
  readKey: CryptoKeyPair
  writeKey: CryptoKeyPair

  constructor(readKey: CryptoKeyPair, writeKey: CryptoKeyPair, cfg: Config) {
    this.cfg = cfg
    this.readKey = readKey
    this.writeKey = writeKey
  }

  async sign(msg: string, charSize: CharSize = 16): Promise<string> {
    const sigBytes = await operations.signBytes(
      utils.strToArrBuf(msg, charSize),
      this.writeKey.privateKey,
      this.cfg.hashAlg
    )
    return utils.arrBufToBase64(sigBytes)
  }

  async verify(
    msg: string,
    sig: string,
    publicKey: string,
    charSize: CharSize = 16
  ): Promise<boolean> {
    const pubkey = await keys.importPublicKey(publicKey, this.cfg.curve, KeyUse.Write)
    return operations.verifyBytes(
      utils.strToArrBuf(msg, charSize),
      utils.base64ToArrBuf(sig),
      pubkey,
      this.cfg.hashAlg
    )
  }

  async encrypt(
    msg: string,
    publicKey: string,
    charSize: CharSize = 16
  ): Promise<string> {
    const pubkey = await keys.importPublicKey(publicKey, this.cfg.curve, KeyUse.Read)
    const cipherText = await operations.encryptBytes(
      utils.strToArrBuf(msg, charSize),
      this.readKey.privateKey,
      pubkey,
      this.cfg.symmAlg
    )
    return utils.arrBufToBase64(cipherText)
  }

  async decrypt(
    cipherText: string,
    publicKey: string,
    charSize: CharSize = 16
  ): Promise<String> {
    const pubkey = await keys.importPublicKey(publicKey, this.cfg.curve, KeyUse.Read)
    const msgBytes = await operations.decryptBytes(
      utils.base64ToArrBuf(cipherText),
      this.readKey.privateKey,
      pubkey,
      this.cfg.symmAlg
    )
    return utils.arrBufToStr(msgBytes, charSize)
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
  ECCKeyStore
}
