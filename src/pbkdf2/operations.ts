import { webcrypto } from 'one-webcrypto';
import { HashAlg, SymmKey, SymmKeyOpts, ExportKeyFormat } from '../types';
import {
  DEFAULT_HASH_ALG,
  DEFAULT_SYMM_ALG,
  DEFAULT_SYMM_KEY_LENGTH,
} from '../constants';

/**
 * Derive a symmetric key from an input keying material (IKM) using HKDF.
 * @param ikm Input keying material. This need not be key material with high entropy. Passwords are safe.
 * @param salt Optional salt value (a non-secret random value). If not provided, it is set to a string of hash length zeros.
 * @param infoStr Optional context and application specific information.
 * @param hashAlg Hash algorithm to use. Default is SHA-256.
 * @param uses Key usage. Default is encrypt/decrypt.
 * @param opts Optional symmetric key options.
 */

export async function deriveKey(
  ikm: string,
  salt: ArrayBuffer,
  hashAlg: HashAlg = DEFAULT_HASH_ALG,
  uses: KeyUsage[] = ['encrypt', 'decrypt'],
  opts?: Partial<SymmKeyOpts>
): Promise<SymmKey> {
  const enc = new TextEncoder();
  return await webcrypto.subtle
    .importKey(ExportKeyFormat.RAW, enc.encode(ikm), 'PBKDF2', false, [
      'deriveBits',
      'deriveKey',
    ])
    .then((baseKey) =>
      webcrypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 100000,
          hash: hashAlg,
        },
        baseKey,
        {
          name: opts?.alg || DEFAULT_SYMM_ALG,
          length: opts?.length || DEFAULT_SYMM_KEY_LENGTH,
        },
        false,
        uses
      )
    );
}

export default {
  deriveKey,
};
