import aes from '../aes'
import idb from '../idb'
import utils from '../utils'
import { symmKeyOpts } from '../config'
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

  async importSymmKey(keyStr: string, keyName: string): Promise<void> {
    const key = await aes.importKey(keyStr, symmKeyOpts(this.cfg))
    await idb.putKey(keyName, key)
  }

  async exportSymmKey(keyName: string): Promise<string> {
    const key = await aes.getKey(keyName, symmKeyOpts(this.cfg))
    return aes.exportKey(key)
  }

  async encryptWithSymmKey(msg: string, keyName: string): Promise<string> {
    const key = await aes.getKey(keyName, symmKeyOpts(this.cfg))
    const cipherText = await aes.encryptBytes(
      utils.strToArrBuf(msg, this.cfg.charSize),
      key,
      symmKeyOpts(this.cfg)
    )
    return utils.arrBufToBase64(cipherText)
  }

  async decryptWithSymmKey(cipherText: string, keyName: string): Promise<string> {
    const key = await aes.getKey(keyName, symmKeyOpts(this.cfg))
    const msgBytes = await aes.decryptBytes(
      utils.base64ToArrBuf(cipherText),
      key,
      symmKeyOpts(this.cfg)
    )
    return utils.arrBufToStr(msgBytes, this.cfg.charSize)
  }

}
