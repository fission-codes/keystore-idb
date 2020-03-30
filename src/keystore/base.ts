import aes from '../aes'
import idb from '../idb'
import utils from '../utils'
import { Config, SymmKeyOpts } from '../types'

export default class KeyStoreBase {
  cfg: Config
  readKey: CryptoKeyPair
  writeKey: CryptoKeyPair

  constructor(readKey: CryptoKeyPair, writeKey: CryptoKeyPair, cfg: Config) {
    this.cfg = cfg
    this.readKey = readKey
    this.writeKey = writeKey
  }

  async keyExists(keyName: string): Promise<boolean> {
    return idb.exists(keyName)
  }

  symmKeyOpts(): Partial<SymmKeyOpts> {
    return { alg: this.cfg.symmAlg, length: this.cfg.symmLen }
  }

  async importSymmKey(keyStr: string, keyName: string): Promise<void> {
    const key = await aes.importKey(keyStr, this.symmKeyOpts())
    await idb.putKey(keyName, key)
  }

  async exportSymmKey(keyName: string): Promise<string> {
    const key = await aes.getKey(keyName, this.symmKeyOpts())
    return aes.exportKey(key)
  }

  async encryptWithSymmKey(msg: string, keyName: string): Promise<string> {
    const key = await aes.getKey(keyName, this.symmKeyOpts())
    const cipherText = await aes.encryptBytes(
      utils.strToArrBuf(msg, this.cfg.charSize),
      key,
      this.symmKeyOpts()
    )
    return utils.arrBufToBase64(cipherText)
  }

  async decryptWithSymmKey(msg: string, keyName: string): Promise<string> {
    const key = await aes.getKey(keyName, this.symmKeyOpts())
    const cipherText = await aes.decryptBytes(
      utils.base64ToArrBuf(msg),
      key,
      this.symmKeyOpts()
    )
    return utils.arrBufToStr(cipherText, this.cfg.charSize)
  }

}
