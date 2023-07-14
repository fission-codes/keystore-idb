import { webcrypto } from 'one-webcrypto';
import utils from '../utils.js';
import {
  DEFAULT_ECC_CURVE,
  DEFAULT_HASH_ALG,
  DEFAULT_SALT_LENGTH,
  ECC_EXCHANGE_ALG,
  ECC_WRITE_ALG,
} from '../constants.js';
import {
  EccCurve,
  KeyUse,
  PublicKey,
  ExportKeyFormat,
  SymmKey,
  PrivateKey,
  EscrowedKeyPair,
} from '../types.js';
import { checkValidKeyUse } from '../errors.js';

/**
 * Generate a new ECC key pair
 * @param curve The curve to use
 * @param use The use of the key pair, either exchange or write
 */
export async function genKeyPair(
  curve: EccCurve,
  use: KeyUse
): Promise<CryptoKeyPair> {
  checkValidKeyUse(use);
  const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALG : ECC_WRITE_ALG;
  const uses: KeyUsage[] =
    use === KeyUse.Exchange ? ['deriveBits'] : ['sign', 'verify'];
  return webcrypto.subtle.generateKey(
    { name: alg, namedCurve: curve },
    true,
    uses
  );
}

/**
 * Import a public key from a base64 string
 * @param base64Key The base64 encoded public key
 * @param curve The curve to use
 * @param use The use of the key pair, either exchange or write
 */
export async function importPublicKey(
  base64Key: string,
  curve: EccCurve,
  use: KeyUse
): Promise<PublicKey> {
  checkValidKeyUse(use);
  const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALG : ECC_WRITE_ALG;
  const uses: KeyUsage[] =
    use === KeyUse.Exchange ? ['deriveBits'] : ['verify'];
  const buf = utils.base64ToArrBuf(base64Key);
  return webcrypto.subtle.importKey(
    ExportKeyFormat.SPKI,
    buf,
    { name: alg, namedCurve: curve },
    true,
    uses
  );
}

/**
 * Export a public key to a base64 string
 * @param publicKey The public key to export
 */
export async function exportPublicKey(publicKey: PublicKey): Promise<string> {
  const exp = await webcrypto.subtle.exportKey(ExportKeyFormat.SPKI, publicKey);
  return utils.arrBufToBase64(exp);
}

export async function fingerprintPublicKey(
  publicKey: PublicKey,
  curve: EccCurve = DEFAULT_ECC_CURVE,
  hashAlg: string = DEFAULT_HASH_ALG
): Promise<string> {
  const publicKeyBytes = new Uint8Array(
    await webcrypto.subtle.exportKey(ExportKeyFormat.RAW, publicKey)
  );
  const size = utils.eccCurveToBitLength(curve);
  // TODO: This does not generalize! It only works for P-384
  const compressedPoint = new Uint8Array(size);
  const x = publicKeyBytes.slice(1, size + 1);
  const y = publicKeyBytes.slice(size + 1);

  // Note:
  // first byte is 0x02 or 0x03 depending on the parity of the
  // y-coordinate, followed by the x coordinate. We can't technically
  // figure out whether the y-coodinate is odd without doing big number
  // arithmetic, but this is a fair approximation.
  compressedPoint[0] = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;
  compressedPoint.set(x, 1);

  const hash = await webcrypto.subtle.digest(hashAlg, compressedPoint);
  return utils.fingerprintFromBuf(new Uint8Array(hash));
}

/**
 * Escrow an asymm key pair with a symmetric key using AES-GCM
 * @param keyPair The key pair to escrow
 * @param wrappingKey The symmetric key to use for wrapping -- This cannot be AES-KW
 * @param salt The salt to use for wrapping
 */
export async function exportEscrowedKeyPair(
  publicKey: PublicKey,
  privateKey: PrivateKey,
  wrappingKey: SymmKey
): Promise<EscrowedKeyPair> {
  const salt = utils.randomBuf(DEFAULT_SALT_LENGTH);
  return {
    publicKeyStr: await exportPublicKey(publicKey as PublicKey),
    wrappedPrivateKeyStr: await webcrypto.subtle
      .wrapKey(ExportKeyFormat.PKCS8, privateKey, wrappingKey, {
        name: 'AES-GCM',
        iv: salt,
      })
      .then((cipherBuf) => utils.joinCipherText(salt, cipherBuf))
      .then(utils.arrBufToBase64),
  };
}

/**
 * Recover an escrowed key pair
 * @param publicKeyStr The public key to recover
 * @param escrowedPrivateKeyStr The wrapped private key to recover
 * @param unwrappingKey The symmetric key to use for unwrapping -- This cannot be AES-KW
 * @param salt The salt to use for unwrapping
 * @param curve The curve to use for the recovered key pair
 * @param use The use of the recovered key pair
 */
export async function importEscrowedKeyPair(
  escrowKeyPair: EscrowedKeyPair,
  unwrappingKey: SymmKey,
  curve: EccCurve,
  use: KeyUse
): Promise<CryptoKeyPair> {
  const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALG : ECC_WRITE_ALG;
  const uses: KeyUsage[] = use === KeyUse.Exchange ? ['deriveBits'] : ['sign'];
  const cipherText = utils.normalizeBase64ToBuf(
    escrowKeyPair.wrappedPrivateKeyStr
  );
  const [iv, cipherBytes] = utils.splitCipherText(cipherText);
  const publicKey = await importPublicKey(
    escrowKeyPair.publicKeyStr,
    curve,
    use
  );
  const privateKey = await webcrypto.subtle.unwrapKey(
    ExportKeyFormat.PKCS8,
    cipherBytes,
    unwrappingKey,
    {
      name: 'AES-GCM',
      iv,
    },
    {
      name: alg,
      namedCurve: curve,
    },
    true,
    uses
  );
  return { publicKey, privateKey };
}

export default {
  genKeyPair,
  importPublicKey,
  exportPublicKey,
  fingerprintPublicKey,
  importEscrowedKeyPair,
  exportEscrowedKeyPair,
};
