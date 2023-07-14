import config from '../config.js';
import IDB from '../idb.js';
import { ECCNotEnabled } from '../errors.js';
import ecc from '../ecc/index.js';
import utils from '../utils.js';
import KeyStoreBase from '../keystore/base.js';
import {
  Config,
  KeyStore,
  PublicKey,
  PrivateKey,
  KeyUse,
  EscrowedKeyPair,
  CipherText,
} from '../types.js';
import { DEFAULT_SYMM_ALG } from '../constants.js';

export default class ECCKeyStore extends KeyStoreBase implements KeyStore {
  static async init(maybeCfg: Partial<Config>): Promise<ECCKeyStore> {
    const eccEnabled = await config.eccEnabled();
    if (!eccEnabled) {
      throw ECCNotEnabled;
    }
    const cfg = config.normalize({
      ...(maybeCfg || {}),
    });
    const { storeName } = cfg;
    const store = IDB.createStore(storeName);
    return new ECCKeyStore(cfg, store);
  }

  // Key Pair Generation
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

  // Public Key Exporters
  async exportPublicExchangeKey(): Promise<string> {
    const keyPair = await this.getExchangeKeyPair();
    return ecc.exportPublicKey(keyPair.publicKey as PublicKey);
  }
  async exportPublicWriteKey(): Promise<string> {
    const keyPair = await this.getWriteKeyPair();
    return ecc.exportPublicKey(keyPair.publicKey as PublicKey);
  }
  async fingerprintPublicExchangeKey(): Promise<string> {
    const keyPair = await this.getExchangeKeyPair();
    return ecc.fingerprintPublicKey(keyPair.publicKey as PublicKey);
  }
  async fingerprintPublicWriteKey(): Promise<string> {
    const keyPair = await this.getWriteKeyPair();
    return ecc.fingerprintPublicKey(keyPair.publicKey as PublicKey);
  }

  // Key Escrow and Recovery

  async exportEscrowedExchangeKeyPair(
    cfg?: Partial<Config>
  ): Promise<EscrowedKeyPair> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const keyPair = await this.getExchangeKeyPair();
    const escrowKey = await this.getSymmKey(mergedCfg.escrowKeyName);
    return await ecc.exportEscrowedKeyPair(
      keyPair.publicKey as PublicKey,
      keyPair.privateKey as PrivateKey,
      escrowKey
    );
  }
  async exportEscrowedWriteKeyPair(
    cfg?: Partial<Config>
  ): Promise<EscrowedKeyPair> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const keyPair = await this.getWriteKeyPair();
    const escrowKey = await this.getSymmKey(mergedCfg.escrowKeyName);
    return await ecc.exportEscrowedKeyPair(
      keyPair.publicKey as PublicKey,
      keyPair.privateKey as PrivateKey,
      escrowKey
    );
  }
  async importEscrowedExchangeKeyPair(
    escrowKeyPair: EscrowedKeyPair,
    cfg?: Partial<Config>
  ): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const escrowKey = await this.getSymmKey(mergedCfg.escrowKeyName);
    await IDB.createIfDoesNotExist(
      this.cfg.exchangeKeyPairName,
      () =>
        ecc.importEscrowedKeyPair(
          escrowKeyPair,
          escrowKey,
          mergedCfg.curve,
          KeyUse.Exchange
        ),
      this.store
    );
  }

  async importEscrowedWriteKeyPair(
    escrowKeyPair: EscrowedKeyPair,
    cfg?: Partial<Config>
  ): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const escrowKey = await this.getSymmKey(mergedCfg.escrowKeyName);
    await IDB.createIfDoesNotExist(
      this.cfg.writeKeyPairName,
      () =>
        ecc.importEscrowedKeyPair(
          escrowKeyPair,
          escrowKey,
          mergedCfg.curve,
          KeyUse.Write
        ),
      this.store
    );
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
    b64DerivationSaltStr: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const derivationSalt = utils.base64ToArrBuf(b64DerivationSaltStr);
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
        derivationSalt,
        mergedCfg.curve,
        mergedCfg.hashAlg,
        mergedCfg.charSize,
        symmKeyOpts
      )
    );
  }
  async decrypt(
    cipherText: string,
    publicKey: string,
    derivationSaltStr: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const symmKeyOpts = config.symmKeyOpts(mergedCfg);
    const derivationSalt = utils.base64ToArrBuf(derivationSaltStr);
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
        derivationSalt,
        mergedCfg.curve,
        mergedCfg.hashAlg,
        symmKeyOpts
      ),
      mergedCfg.charSize
    );
  }
  async wrapKey(
    key: CryptoKey,
    publicKey: string,
    derivationSaltStr: string,
    cfg?: Partial<Config>
  ): Promise<CipherText> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const symmKeyOpts = config.symmKeyOpts(mergedCfg);
    const derivationSalt = utils.base64ToArrBuf(derivationSaltStr);
    const exchangeKey = await this.getExchangeKeyPair();
    const importedPublicKey = await ecc.importPublicKey(
      publicKey,
      mergedCfg.curve,
      KeyUse.Exchange
    );
    return await ecc.wrapKey(
      key,
      exchangeKey.privateKey as PrivateKey,
      importedPublicKey,
      derivationSalt,
      mergedCfg.curve,
      mergedCfg.hashAlg,
      symmKeyOpts
    );
  }
  async unwrapKey(
    wrappedKey: CipherText,
    publicKey: string,
    derivationSaltStr: string,
    keyParams: AlgorithmIdentifier = { name: DEFAULT_SYMM_ALG },
    extractable = false,
    uses: KeyUsage[] = ['encrypt', 'decrypt'],
    cfg?: Partial<Config>
  ): Promise<CryptoKey> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const symKeyOpts = config.symmKeyOpts(mergedCfg);
    const exchangeKey = await this.getExchangeKeyPair();
    const importedPublicKey = await ecc.importPublicKey(
      publicKey,
      mergedCfg.curve,
      KeyUse.Exchange
    );
    return await ecc.unwrapKey(
      wrappedKey,
      exchangeKey.privateKey as PrivateKey,
      importedPublicKey,
      utils.base64ToArrBuf(derivationSaltStr),
      keyParams,
      extractable,
      uses,
      mergedCfg.curve,
      mergedCfg.hashAlg,
      symKeyOpts
    );
  }
}
