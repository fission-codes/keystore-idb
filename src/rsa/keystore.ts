import keys from './keys'
import operations from './operations'
import config from '../config'
import utils from '../utils'
import KeyStoreBase from '../keystore/base'
import { KeyStore, PartialConfig, KeyUse, CharSize, CryptoSystem } from '../types'

export class RSAKeyStore extends KeyStoreBase implements KeyStore {

  async sign(msg: string, charSize: CharSize = 16): Promise<string> {
    const sigBytes = await operations.signBytes(
      utils.strToArrBuf(msg, charSize),
      this.writeKey.privateKey
    )
    return utils.arrBufToBase64(sigBytes)
  }

  async verify(
    msg: string,
    sig: string,
    publicKey: string,
    charSize: CharSize = 16
  ): Promise<boolean> {
    const pubkey = await keys.importPublicKey(publicKey, this.cfg.hashAlg, KeyUse.Write)
    return operations.verifyBytes(
      utils.strToArrBuf(msg, charSize),
      utils.base64ToArrBuf(sig),
      pubkey
    )
  }

  async encrypt(
    msg: string,
    publicKey: string,
    charSize: CharSize = 16
  ): Promise<string> {
    const pubkey = await keys.importPublicKey(publicKey, this.cfg.hashAlg, KeyUse.Read)
    const cipherText = await operations.encryptBytes(
      utils.strToArrBuf(msg, charSize),
      pubkey
    )
    return utils.arrBufToBase64(cipherText)
  }

  async decrypt(
    cipherText: string,
    publicKey?: string, //unused param so that keystore interfaces match
    charSize: CharSize = 16
  ): Promise<string> {
    const msgBytes = await operations.decryptBytes(
      utils.base64ToArrBuf(cipherText),
      this.readKey.privateKey
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

export async function init(maybeCfg?: PartialConfig): Promise<RSAKeyStore> {
  const cfg = config.normalize({
    ...(maybeCfg || {}),
    type: CryptoSystem.RSA
  })
  const { rsaSize, hashAlg, readKeyName, writeKeyName } = cfg
  const readKey = await keys.getKey(rsaSize, hashAlg, readKeyName, KeyUse.Read)
  const writeKey = await keys.getKey(
    rsaSize,
    hashAlg,
    writeKeyName,
    KeyUse.Write
  )
  return new RSAKeyStore(readKey, writeKey, cfg)
}

export default {
  RSAKeyStore,
  init,
}
