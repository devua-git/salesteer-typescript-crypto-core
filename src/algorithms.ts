import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js'
import { hmac as nobleHmac } from '@noble/hashes/hmac.js'
import { pbkdf2Async as noblePbkdf2 } from '@noble/hashes/pbkdf2.js'
import { sha256 as nobleSha256, sha384 as nobleSha384, sha512 as nobleSha512 } from '@noble/hashes/sha2.js'
import { toArrayBuffer, toUint8Array } from './bytes'
import { VaultCryptoGenerationService } from './generation'
import { VaultKey } from './key'

export type CryptoAlgorithmInput = ArrayBuffer | Uint8Array | string

export const SHAAlgorithm = {
  SHA256: 'SHA-256',
  SHA384: 'SHA-384',
  SHA512: 'SHA-512',
} as const
export type SHAAlgorithm = (typeof SHAAlgorithm)[keyof typeof SHAAlgorithm]

export const HKDFKeyLength = {
  256: 256,
} as const
export type HKDFKeyLength = (typeof HKDFKeyLength)[keyof typeof HKDFKeyLength]

export interface VaultCryptoAlgorithmService {
  SHA(params: { message: CryptoAlgorithmInput; hash: SHAAlgorithm }): Uint8Array<ArrayBuffer>
  PBKDF2(params: {
    password: CryptoAlgorithmInput
    salt: CryptoAlgorithmInput
    iterations: number
    hash: SHAAlgorithm
  }): Promise<VaultKey>
  HKDF(params: {
    masterKey: VaultKey
    salt: CryptoAlgorithmInput
    info: CryptoAlgorithmInput
    hash: SHAAlgorithm
    keyLength?: HKDFKeyLength
  }): Promise<VaultKey>
  HMAC(params: {
    key: VaultKey
    message: CryptoAlgorithmInput
    hash: SHAAlgorithm
  }): Promise<Uint8Array<ArrayBuffer>>
}

class DefaultVaultCryptoAlgorithmService implements VaultCryptoAlgorithmService {
  private readonly hashAlgorithmMap = {
    [SHAAlgorithm.SHA256]: nobleSha256,
    [SHAAlgorithm.SHA384]: nobleSha384,
    [SHAAlgorithm.SHA512]: nobleSha512,
  }

  SHA(params: { message: CryptoAlgorithmInput; hash: SHAAlgorithm }): Uint8Array<ArrayBuffer> {
    return this.hashAlgorithmMap[params.hash](toUint8Array(params.message))
  }

  async PBKDF2(params: {
    password: CryptoAlgorithmInput
    salt: CryptoAlgorithmInput
    iterations: number
    hash: SHAAlgorithm
  }): Promise<VaultKey> {
    const key = await noblePbkdf2(
      this.hashAlgorithmMap[params.hash],
      toUint8Array(params.password),
      toUint8Array(params.salt),
      { c: params.iterations },
    )
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw',
      toArrayBuffer(key),
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    )

    return new VaultKey(cryptoKey, VaultCryptoGenerationService.UUID())
  }

  async HKDF(params: {
    masterKey: VaultKey
    salt: CryptoAlgorithmInput
    info: CryptoAlgorithmInput
    hash: SHAAlgorithm
    keyLength?: HKDFKeyLength
  }): Promise<VaultKey> {
    const keyLengthBits = params.keyLength ?? HKDFKeyLength[256]
    const key = nobleHkdf(
      this.hashAlgorithmMap[params.hash],
      await params.masterKey.getKeyBuffer(),
      toUint8Array(params.salt),
      toUint8Array(params.info),
      keyLengthBits / 8,
    )
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw',
      toArrayBuffer(key),
      { name: 'AES-GCM', length: keyLengthBits },
      true,
      ['encrypt', 'decrypt'],
    )

    return new VaultKey(cryptoKey, VaultCryptoGenerationService.UUID())
  }

  async HMAC(params: {
    key: VaultKey
    message: CryptoAlgorithmInput
    hash: SHAAlgorithm
  }): Promise<Uint8Array<ArrayBuffer>> {
    return nobleHmac(
      this.hashAlgorithmMap[params.hash],
      await params.key.getKeyBuffer(),
      toUint8Array(params.message),
    )
  }
}

export const VaultCryptoAlgorithmService: VaultCryptoAlgorithmService = new DefaultVaultCryptoAlgorithmService()
