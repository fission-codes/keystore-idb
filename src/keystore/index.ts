import config from '../config.js';
import IDB from '../idb.js';
import { ECCNotEnabled, KeyDoesNotExist } from '../errors.js';
import aes from '../aes/index.js';
import ecc from '../ecc/index.js';
import idb from '../idb.js';
import utils from '../utils.js';
import * as common from '../common';
import {
  Config,
  KeyStoreInterface,
  ExportKeyFormat,
  PublicKey,
  PrivateKey,
  KeyUse,
} from '../types.js';
import { checkIsKeyPair } from '../errors.js';

export default class KeyStore implements KeyStoreInterface {
  cfg: Config;
  protected store: LocalForage;

  constructor(cfg: Config, store: LocalForage) {
    this.cfg = cfg;
    this.store = store;
  }

  static async init(maybeCfg?: Partial<Config>): Promise<KeyStore> {
    const eccEnabled = await config.eccEnabled();
    if (!eccEnabled) {
      throw ECCNotEnabled;
    }

    const cfg = config.normalize({
      ...(maybeCfg || {}),
    });

    const { storeName } = cfg;
    const store = IDB.createStore(storeName);
    return new KeyStore(cfg, store);
  }

  /* Keystore Management */

  async keyExists(keyName: string): Promise<boolean> {
    const key = await idb.getKey(keyName, this.store);
    return key !== null;
  }
  async keyPairExists(keyPairName: string): Promise<boolean> {
    const keyPair = await idb.getKeypair(keyPairName, this.store);
    return keyPair !== null;
  }
  async deleteKey(keyName: string): Promise<void> {
    return idb.rm(keyName, this.store);
  }
  async clear(): Promise<void> {
    return idb.clear(this.store);
  }

  /* Asymmetric Key Management */

  // Key Generation and Import
  async genExchangeKeyPair(cfg?: Partial<Config>): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg);
    await IDB.createIfDoesNotExist(
      this.cfg.exchangeKeyPairName,
      () => ecc.genKeyPair(mergedCfg.curve, KeyUse.Exchange),
      this.store
    );
  }
  async genWriteKeyPair(cfg?: Partial<Config>): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg);
    await IDB.createIfDoesNotExist(
      this.cfg.writeKeyPairName,
      () => ecc.genKeyPair(mergedCfg.curve, KeyUse.Write),
      this.store
    );
  }
  async unwrapExhangeKeyPair(
    publicKeyStr: string,
    wrappedPrivateKeyStr: string,
    cfg?: Partial<Config> | undefined
  ): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const symmWrappingKeyOpts = config.symmWrappingKeyOpts(mergedCfg);
    const passKey = await this.getSymmKey(this.cfg.passKeyName);
    await IDB.createIfDoesNotExist(
      this.cfg.exchangeKeyPairName,
      () =>
        ecc.importWrappedKeyPair(
          publicKeyStr,
          wrappedPrivateKeyStr,
          passKey,
          mergedCfg.curve,
          KeyUse.Exchange,
          symmWrappingKeyOpts
        ),
      this.store
    );
  }
  async unwrapWriteKeyPair(
    publicKeyStr: string,
    wrappedPrivateKeyStr: string,
    cfg?: Partial<Config> | undefined
  ): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const symmWrappingKeyOpts = config.symmWrappingKeyOpts(mergedCfg);
    const passKey = await this.getSymmKey(this.cfg.passKeyName);
    await IDB.createIfDoesNotExist(
      this.cfg.writeKeyPairName,
      () =>
        ecc.importWrappedKeyPair(
          publicKeyStr,
          wrappedPrivateKeyStr,
          passKey,
          mergedCfg.curve,
          KeyUse.Write,
          symmWrappingKeyOpts
        ),
      this.store
    );
  }

  // Getters and Exporters
  async getExchangeKeyPair(): Promise<CryptoKeyPair> {
    const maybeKey = await idb.getKeypair(
      this.cfg.exchangeKeyPairName,
      this.store
    );
    return checkIsKeyPair(maybeKey);
  }
  async getWriteKeyPair(): Promise<CryptoKeyPair> {
    const maybeKey = await idb.getKeypair(
      this.cfg.writeKeyPairName,
      this.store
    );
    return checkIsKeyPair(maybeKey);
  }
  async exportPublicExchangeKey(): Promise<string> {
    const keyPair = await this.getExchangeKeyPair();
    return common.exportKey(
      keyPair.publicKey as PublicKey,
      ExportKeyFormat.SPKI
    );
  }
  async exportPublicWriteKey(): Promise<string> {
    const keyPair = await this.getWriteKeyPair();
    return common.exportKey(
      keyPair.publicKey as PublicKey,
      ExportKeyFormat.SPKI
    );
  }
  async wrapExchangeKeyPair(): Promise<{
    publicKey: string;
    wrappedPrivateKey: string;
  }> {
    const keyPair = await this.getExchangeKeyPair();
    const passKey = await this.getSymmKey(this.cfg.passKeyName);
    const symmWrappingKeyOpts = config.symmWrappingKeyOpts(this.cfg);
    const publicKey = await this.exportPublicExchangeKey();
    const wrappedPrivateKey = await aes.wrapKey(
      ExportKeyFormat.PKCS8,
      keyPair.privateKey as PrivateKey,
      passKey,
      symmWrappingKeyOpts
    );
    return { publicKey, wrappedPrivateKey };
  }
  async wrapWriteKeyPair(): Promise<{
    publicKey: string;
    wrappedPrivateKey: string;
  }> {
    const keyPair = await this.getWriteKeyPair();
    const passKey = await this.getSymmKey(this.cfg.passKeyName);
    const symmWrappingKeyOpts = config.symmWrappingKeyOpts(this.cfg);
    const publicKey = await this.exportPublicWriteKey();
    const wrappedPrivateKey = await aes.wrapKey(
      ExportKeyFormat.PKCS8,
      keyPair.privateKey as PrivateKey,
      passKey,
      symmWrappingKeyOpts
    );
    return { publicKey, wrappedPrivateKey };
  }

  // Utilities
  async publicExchangeKeyFingerprint(): Promise<string> {
    const keyPair = await this.getExchangeKeyPair();
    const bytes = await common.exportKeyBytes(
      keyPair.publicKey as PublicKey,
      ExportKeyFormat.SPKI
    );
    return utils.fingerprint(bytes);
  }
  async publicWriteKeyFingerprint(): Promise<string> {
    const keyPair = await this.getWriteKeyPair();
    const bytes = await common.exportKeyBytes(
      keyPair.publicKey as PublicKey,
      ExportKeyFormat.SPKI
    );
    return utils.fingerprint(bytes);
  }

  // Key Operations
  async sign(msg: string, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const writeKey = await this.getWriteKeyPair();
    return utils.arrBufToBase64(
      await ecc.sign(
        msg,
        writeKey.privateKey as PrivateKey,
        mergedCfg.charSize,
        mergedCfg.hashAlg
      )
    );
  }
  async verify(
    msg: string,
    sig: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<boolean> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const importedPublicKey = await ecc.importPublicKey(
      publicKey,
      mergedCfg.curve,
      KeyUse.Write
    );
    return ecc.verify(
      msg,
      sig,
      importedPublicKey,
      mergedCfg.charSize,
      mergedCfg.hashAlg
    );
  }
  async encrypt(
    msg: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const symmKeyOpts = config.symmKeyOpts(mergedCfg);
    const exchangeKey = await this.getExchangeKeyPair();
    const importedPublicKey = await ecc.importPublicKey(
      publicKey,
      mergedCfg.curve,
      KeyUse.Exchange
    );
    return utils.arrBufToBase64(
      await ecc.encrypt(
        msg,
        exchangeKey.privateKey as PrivateKey,
        importedPublicKey,
        mergedCfg.charSize,
        symmKeyOpts
      )
    );
  }
  async decrypt(
    cipherText: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const symmKeyOpts = config.symmKeyOpts(mergedCfg);
    const exchangeKey = await this.getExchangeKeyPair();
    const importedPublicKey = await ecc.importPublicKey(
      publicKey,
      mergedCfg.curve,
      KeyUse.Exchange
    );
    return utils.arrBufToStr(
      await ecc.decrypt(
        cipherText,
        exchangeKey.privateKey as PrivateKey,
        importedPublicKey,
        symmKeyOpts
      ),
      mergedCfg.charSize
    );
  }
  async wrapKey(
    key: CryptoKey,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const symWrappingKeyOpts = config.symmWrappingKeyOpts(mergedCfg);
    const exchangeKey = await this.getExchangeKeyPair();
    const importedPublicKey = await ecc.importPublicKey(
      publicKey,
      mergedCfg.curve,
      KeyUse.Exchange
    );
    return await ecc.wrapKey(
      ExportKeyFormat.RAW,
      key,
      exchangeKey.privateKey as PrivateKey,
      importedPublicKey,
      symWrappingKeyOpts
    );
  }
  async unwrapKey(
    wrappedKey: string,
    publicKey: string,
    keyParams: AlgorithmIdentifier,
    uses: KeyUsage[],
    cfg?: Partial<Config>
  ): Promise<CryptoKey> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const symWrappingKeyOpts = config.symmWrappingKeyOpts(mergedCfg);
    const exchangeKey = await this.getExchangeKeyPair();
    const importedPublicKey = await ecc.importPublicKey(
      publicKey,
      mergedCfg.curve,
      KeyUse.Exchange
    );
    return await ecc.unwrapKey(
      ExportKeyFormat.RAW,
      wrappedKey,
      exchangeKey.privateKey as PrivateKey,
      importedPublicKey,
      keyParams,
      uses,
      symWrappingKeyOpts
    );
  }

  /* Wrapping Key Management */

  // Key Generation and Import
  async derivePassKey(
    seedphrase: string,
    saltStr?: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const salt = saltStr
      ? utils.base64ToArrBuf(saltStr)
      : utils.randomSalt(mergedCfg.saltLength);
    const key = await aes.deriveWrappingKey(
      seedphrase,
      salt,
      mergedCfg.hashAlg,
      config.symmWrappingKeyOpts(mergedCfg)
    );
    await idb.put(this.cfg.passKeyName, key, this.store);
    return saltStr ?? utils.arrBufToBase64(salt);
  }

  /* Symmetric Key Management */

  // Key Generation and Import
  async genSymmKey(keyName: string, cfg?: Partial<Config>): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg);
    await IDB.createIfDoesNotExist(
      keyName,
      () => aes.genKey(config.symmKeyOpts(mergedCfg)),
      this.store
    );
  }
  async importSymmKey(
    keyStr: string,
    keyName: string,
    cfg?: Partial<Config>
  ): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const key = await aes.importKey(keyStr, config.symmKeyOpts(mergedCfg));
    await idb.put(keyName, key, this.store);
  }
  async deriveSymmKey(
    keyName: string,
    seedphrase: string,
    salt: ArrayBuffer,
    cfg?: Partial<Config>
  ): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const key = await aes.deriveKey(
      seedphrase,
      salt,
      mergedCfg.hashAlg,
      config.symmKeyOpts(mergedCfg)
    );
    await idb.put(keyName, key, this.store);
  }

  // Getters and Exporters
  async getSymmKey(keyName: string): Promise<CryptoKey> {
    const maybeKey = await idb.getKey(keyName, this.store);
    if (maybeKey === null) {
      throw KeyDoesNotExist;
    }
    return maybeKey;
  }

  async exportSymmKey(keyName: string): Promise<string> {
    const key = await this.getSymmKey(keyName);
    return common.exportKey(key, ExportKeyFormat.RAW);
  }

  // Key Operations
  async encryptWithSymmKey(
    msg: string,
    keyName: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const key = await this.getSymmKey(keyName);
    const cipherText = await aes.encryptBytes(
      utils.strToArrBuf(msg, mergedCfg.charSize),
      key,
      config.symmKeyOpts(mergedCfg)
    );
    return utils.arrBufToBase64(cipherText);
  }
  async decryptWithSymmKey(
    cipherText: string,
    keyName: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const key = await this.getSymmKey(keyName);
    const msgBytes = await aes.decryptBytes(
      utils.base64ToArrBuf(cipherText),
      key,
      config.symmKeyOpts(mergedCfg)
    );
    return utils.arrBufToStr(msgBytes, mergedCfg.charSize);
  }
}
