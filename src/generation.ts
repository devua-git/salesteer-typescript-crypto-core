import { VaultKey } from './key'
import { randomUUID } from './random'

export interface VaultCryptoGenerationService {
  UUID(): string
  generateIv(): Uint8Array<ArrayBuffer>
  generateSymmetricKey(): Promise<VaultKey>
  generateKeyPair(): Promise<{ publicKey: VaultKey; privateKey: VaultKey }>
}

class DefaultVaultCryptoGenerationService implements VaultCryptoGenerationService {
  UUID(): string {
    return randomUUID()
  }

  generateIv(): Uint8Array<ArrayBuffer> {
    return globalThis.crypto.getRandomValues(new Uint8Array(12))
  }

  async generateSymmetricKey(): Promise<VaultKey> {
    const key = await globalThis.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    )

    return new VaultKey(key, this.UUID())
  }

  async generateKeyPair(): Promise<{ publicKey: VaultKey; privateKey: VaultKey }> {
    const keyId = this.UUID()
    const keyPair = await globalThis.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
      },
      true,
      ['encrypt', 'decrypt'],
    )

    return {
      publicKey: new VaultKey(keyPair.publicKey, keyId),
      privateKey: new VaultKey(keyPair.privateKey, keyId),
    }
  }
}

export const VaultCryptoGenerationService: VaultCryptoGenerationService = new DefaultVaultCryptoGenerationService()
