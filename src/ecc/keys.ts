import { webcrypto } from 'one-webcrypto';
import utils from '../utils.js';
import { ECC_EXCHANGE_ALG, ECC_WRITE_ALG } from '../constants.js';
import {
  EccCurve,
  KeyUse,
  PublicKey,
  ExportKeyFormat,
  SymmWrappingKey,
  SymmWrappingKeyOpts,
} from '../types.js';
import { checkValidKeyUse } from '../errors.js';
import * as aes from '../aes/index.js';

export async function genKeyPair(
  curve: EccCurve,
  use: KeyUse
): Promise<CryptoKeyPair> {
  checkValidKeyUse(use);
  const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALG : ECC_WRITE_ALG;
  const uses: KeyUsage[] =
    use === KeyUse.Exchange ? ['deriveKey', 'deriveBits'] : ['sign', 'verify'];
  return webcrypto.subtle.generateKey(
    { name: alg, namedCurve: curve },
    true,
    uses
  );
}

export async function importPublicKey(
  base64Key: string,
  curve: EccCurve,
  use: KeyUse
): Promise<PublicKey> {
  checkValidKeyUse(use);
  const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALG : ECC_WRITE_ALG;
  const uses: KeyUsage[] = use === KeyUse.Exchange ? [] : ['verify'];
  const buf = utils.base64ToArrBuf(base64Key);
  return webcrypto.subtle.importKey(
    ExportKeyFormat.SPKI,
    buf,
    { name: alg, namedCurve: curve },
    true,
    uses
  );
}

export async function importWrappedKeyPair(
  base64PublicKeyStr: string,
  base64WrappedPrivateKeyStr: string,
  unwrappingKey: SymmWrappingKey,
  curve: EccCurve,
  use: KeyUse,
  opts?: Partial<SymmWrappingKeyOpts>
): Promise<CryptoKeyPair> {
  const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALG : ECC_WRITE_ALG;
  const uses: KeyUsage[] =
    use === KeyUse.Exchange ? ['deriveKey', 'deriveBits'] : ['sign', 'verify'];
  const publicKey = await importPublicKey(base64PublicKeyStr, curve, use);
  const privateKey = await aes.unwrapKey(
    ExportKeyFormat.PKCS8,
    base64WrappedPrivateKeyStr,
    unwrappingKey,
    { name: alg, namedCurve: curve } as EcKeyImportParams,
    true,
    uses,
    opts
  );
  return { publicKey, privateKey };
}

export default {
  genKeyPair,
  importPublicKey,
  importWrappedKeyPair,
};
