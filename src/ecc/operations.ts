import aes from '../aes/index.js';
import utils, {
  normalizeBase64ToBuf,
  normalizeUnicodeToBuf,
} from '../utils.js';
import {
  DEFAULT_CHAR_SIZE,
  DEFAULT_ECC_CURVE,
  DEFAULT_HASH_ALG,
  ECC_EXCHANGE_ALG,
  ECC_WRITE_ALG,
} from '../constants.js';
import hkdf from '../hkdf/index.js';
import {
  CharSize,
  Msg,
  PrivateKey,
  PublicKey,
  HashAlg,
  SymmKey,
  SymmKeyOpts,
  EccCurve,
  CipherText,
} from '../types.js';
import { webcrypto } from 'one-webcrypto';

/**
 * Sign a message with an ECSDSA private key
 * @param msg The message to sign
 * @param privateKey The private key to use for signing
 * @param charSize The character size to use for normalization
 * @param hashAlg The hash algorithm to use for signing
 * @returns The signature as an ArrayBuffer
 */
export async function sign(
  msg: Msg,
  privateKey: PrivateKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG
): Promise<ArrayBuffer> {
  return webcrypto.subtle.sign(
    { name: ECC_WRITE_ALG, hash: { name: hashAlg } },
    privateKey,
    normalizeUnicodeToBuf(msg, charSize)
  );
}

/**
 * Verify a message with an ECDSA public key
 * @param msg The message to verify
 * @param sig The signature to verify
 * @param publicKey The public key to use for verification
 * @param charSize The character size to use for normalization
 * @param hashAlg The hash algorithm to use for verification
 * @returns A promise that resolves to a boolean indicating whether the signature is valid
 */
export async function verify(
  msg: Msg,
  sig: Msg,
  publicKey: PublicKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG
): Promise<boolean> {
  return webcrypto.subtle.verify(
    { name: ECC_WRITE_ALG, hash: { name: hashAlg } },
    publicKey,
    normalizeBase64ToBuf(sig),
    normalizeUnicodeToBuf(msg, charSize)
  );
}

/**
 * Encrypt a message with a shared public key and your own private key
 * @param msg The message to encrypt
 * @param privateKey Your private key
 * @param publicKey The public key to encrypt with
 * @param derivationSalt The salt to use for key derivation
 * @param charSize The character size to use for normalization
 * @param opts The options for encryption
 * @throws {UnsupportedSymmCrypto} If the symmetric algorithm is not supported
 */
export async function encrypt(
  msg: Msg,
  privateKey: PrivateKey,
  publicKey: PublicKey,
  derivationSalt: ArrayBuffer,
  curve: EccCurve = DEFAULT_ECC_CURVE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG,
  charSize: CharSize = DEFAULT_CHAR_SIZE,
  opts?: Partial<SymmKeyOpts>
): Promise<ArrayBuffer> {
  const cipherKey = await getSharedKey(
    privateKey,
    publicKey,
    derivationSalt,
    ['encrypt'],
    'shared-encryption-key',
    curve,
    hashAlg,
    opts
  );
  return aes.encryptBytes(
    normalizeUnicodeToBuf(msg, charSize),
    cipherKey,
    opts
  );
}

/**
 * Decrypt a message with a shared public key and your own private key
 * @param msg The message to decrypt
 * @param privateKey Your private key
 * @param publicKey The public key to decrypt with
 * @param derivationSalt The salt to use for key derivation
 * @param curve The curve to use for key derivation
 * @param charSize The character size to use for normalization
 * @param opts The options for decryption
 * @returns The decrypted message as a string
 * @throws {InvalidCipherTextLength} If the cipher text is not the correct length
 * @throws {UnsupportedSymmCrypto} If the symmetric algorithm is not supported
 */
export async function decrypt(
  msg: Msg,
  privateKey: PrivateKey,
  publicKey: PublicKey,
  derivationSalt: ArrayBuffer,
  curve: EccCurve = DEFAULT_ECC_CURVE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG,
  opts?: Partial<SymmKeyOpts>
): Promise<ArrayBuffer> {
  const cipherKey = await getSharedKey(
    privateKey,
    publicKey,
    derivationSalt,
    ['decrypt'],
    'shared-encryption-key',
    curve,
    hashAlg,
    opts
  );
  return aes.decryptBytes(normalizeBase64ToBuf(msg), cipherKey, opts);
}

/**
 * Wrap a key with a shared public key and your own private key
 * @param key The key to wrap
 * @param privateKey Your private key
 * @param publicKey The public key to wrap with
 * @param derivationSalt The salt to use for key derivation
 * @param curve The curve to use for key derivation
 * @param charSize The character size to use for normalization
 * @param opts The options for wrapping
 * @returns The wrapped key as a CipherText (which is just an ArrayBuffer)
 */
export async function wrapKey(
  key: CryptoKey,
  privateKey: PrivateKey,
  publicKey: PublicKey,
  derivationSalt: ArrayBuffer,
  curve: EccCurve = DEFAULT_ECC_CURVE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG,
  opts?: Partial<SymmKeyOpts>
): Promise<CipherText> {
  const cipherKey = await getSharedKey(
    privateKey,
    publicKey,
    derivationSalt,
    ['wrapKey'],
    'shared-encryption-key',
    curve,
    hashAlg,
    opts
  );
  return aes.wrapKey(key, cipherKey);
}

/**
 * Unwrap a key with a shared public key and your own private key
 * @param key The key to unwrap
 * @param privateKey Your private key
 * @param publicKey The public key to unwrap with
 * @param derivationSalt The salt to use for key derivation
 * @param unwrappedKeyAlgParams The algorithm parameters for the unwrapped key
 * @param extractable Whether or not the unwrapped key is extractable
 * @param keyUsages The key usages for the unwrapped key
 * @param curve The curve to use for key derivation
 * @param charSize The character size to use for normalization
 * @param opts The options for unwrapping
 * @returns The unwrapped key as a CryptoKey
 */
export async function unwrapKey(
  key: CipherText,
  privateKey: PrivateKey,
  publicKey: PublicKey,
  derivationSalt: ArrayBuffer,
  unwrappedKeyAlgParams: AlgorithmIdentifier,
  extractable: boolean,
  keyUsages: KeyUsage[],
  curve: EccCurve = DEFAULT_ECC_CURVE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG,
  opts?: Partial<SymmKeyOpts>
): Promise<CryptoKey> {
  const cipherKey = await getSharedKey(
    privateKey,
    publicKey,
    derivationSalt,
    ['unwrapKey'],
    'shared-encryption-key',
    curve,
    hashAlg,
    opts
  );
  return aes.unwrapKey(
    key,
    cipherKey,
    unwrappedKeyAlgParams,
    extractable,
    keyUsages
  );
}

/* Key Derivation Helpers */

async function getSharedKey(
  privateKey: PrivateKey,
  publicKey: PublicKey,
  derivationSalt: ArrayBuffer,
  uses: KeyUsage[],
  keyInfo: string,
  curve: EccCurve = DEFAULT_ECC_CURVE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG,
  opts?: Partial<SymmKeyOpts>
): Promise<SymmKey> {
  const bitLength = utils.eccCurveToBitLength(curve);
  return webcrypto.subtle
    .deriveBits(
      { name: ECC_EXCHANGE_ALG, public: publicKey },
      privateKey,
      bitLength
    )
    .then((bits) =>
      hkdf.deriveKey(bits, derivationSalt, keyInfo, hashAlg, uses, opts)
    );
}

export default {
  sign,
  verify,
  encrypt,
  decrypt,
  wrapKey,
  unwrapKey,
};
