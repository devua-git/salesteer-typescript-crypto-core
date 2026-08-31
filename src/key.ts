import { parse, stringify } from 'superjson'
import { encodeBase64 } from './base64'
import { toArrayBuffer } from './bytes'

const keyTypeToFormatMap: Record<KeyType, 'raw' | 'spki' | 'pkcs8'> = {
  secret: 'raw',
  public: 'spki',
  private: 'pkcs8',
}

export type VaultKeyEncodedPayload = {
  kid: string
  format: 'raw' | 'spki' | 'pkcs8'
  algorithm: KeyAlgorithm
  usages: KeyUsage[]
  key: Uint8Array
}

export class VaultKey {
  constructor(readonly key: CryptoKey, public kid: string) {
    if (!key.extractable) {
      throw new Error('Key is not extractable')
    }
  }

  async getKeyBuffer(): Promise<Uint8Array> {
    const keyBuffer = await globalThis.crypto.subtle.exportKey(
      keyTypeToFormatMap[this.key.type],
      this.key,
    )

    return new Uint8Array(keyBuffer)
  }

  async getKeyBase64(): Promise<string> {
    return encodeBase64(await this.getKeyBuffer())
  }

  async getPayloadBuffer(): Promise<Uint8Array> {
    const encodedPayload: VaultKeyEncodedPayload = {
      kid: this.kid,
      format: keyTypeToFormatMap[this.key.type],
      algorithm: this.key.algorithm,
      usages: this.key.usages,
      key: await this.getKeyBuffer(),
    }

    return new TextEncoder().encode(stringify(encodedPayload))
  }

  static async fromPayloadBuffer(payload: Uint8Array): Promise<VaultKey> {
    const encodedPayload = parse<VaultKeyEncodedPayload>(
      new TextDecoder().decode(payload),
    )

    return this.fromPayload(encodedPayload)
  }

  static async fromPayload(encodedPayload: VaultKeyEncodedPayload): Promise<VaultKey> {
    const key = await globalThis.crypto.subtle.importKey(
      encodedPayload.format,
      toArrayBuffer(encodedPayload.key),
      encodedPayload.algorithm,
      true,
      encodedPayload.usages,
    )

    return new VaultKey(key, encodedPayload.kid)
  }
}
