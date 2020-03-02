import { Config } from '../types'

export default class KeyStoreBase {
  cfg: Config
  readKey: CryptoKeyPair
  writeKey: CryptoKeyPair

  constructor(readKey: CryptoKeyPair, writeKey: CryptoKeyPair, cfg: Config) {
    this.cfg = cfg
    this.readKey = readKey
    this.writeKey = writeKey
  }
}
