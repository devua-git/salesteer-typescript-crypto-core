import { SHAAlgorithm, VaultCryptoAlgorithmService } from './algorithms'
import { encodeBase64 } from './base64'
import { VaultCryptoService } from './crypto'
import { VaultCryptoGenerationService } from './generation'
import { VaultKey } from './key'

export interface VaultKeyManagementService {
  deriveMasterKey(
    password: string,
    salt: string,
    iterations: number,
  ): Promise<{ streatchedMasterKey: VaultKey; masterKey: VaultKey }>
  hashMasterPassword(
    masterKey: VaultKey,
    password: string,
    iterations: number,
  ): Promise<string>
  encryptKey(keyToEncrypt: VaultKey, keyToEncryptWith: VaultKey): Promise<string>
  decryptKey(payload: string, keyToDecryptWith: VaultKey): Promise<VaultKey>
  generateEncryptedKeyPair(
    keyToEncryptWith: VaultKey,
  ): Promise<{ publicKey: VaultKey; encryptedPrivateKey: string }>
}

class DefaultVaultKeyManagementService implements VaultKeyManagementService {
  async deriveMasterKey(
    password: string,
    salt: string,
    iterations: number,
  ): Promise<{ streatchedMasterKey: VaultKey; masterKey: VaultKey }> {
    const masterKey = await VaultCryptoAlgorithmService.PBKDF2({
      password,
      salt,
      iterations,
      hash: SHAAlgorithm.SHA256,
    })
    const streatchedMasterKey = await VaultCryptoAlgorithmService.HKDF({
      masterKey,
      salt,
      info: 'vault-streatched-master-key',
      hash: SHAAlgorithm.SHA256,
    })

    return { masterKey, streatchedMasterKey }
  }

  async hashMasterPassword(
    masterKey: VaultKey,
    password: string,
    iterations: number,
  ): Promise<string> {
    const partialHashedPassword = await VaultCryptoAlgorithmService.PBKDF2({
      password: await masterKey.getKeyBuffer(),
      salt: password,
      iterations,
      hash: SHAAlgorithm.SHA256,
    })
    const hmac = await VaultCryptoAlgorithmService.HMAC({
      key: partialHashedPassword,
      message: password,
      hash: SHAAlgorithm.SHA256,
    })

    return encodeBase64(hmac)
  }

  async encryptKey(keyToEncrypt: VaultKey, keyToEncryptWith: VaultKey): Promise<string> {
    return VaultCryptoService.encrypt(
      await keyToEncrypt.getPayloadBuffer(),
      keyToEncryptWith,
    )
  }

  async decryptKey(payload: string, keyToDecryptWith: VaultKey): Promise<VaultKey> {
    return VaultKey.fromPayloadBuffer(
      await VaultCryptoService.decrypt(payload, keyToDecryptWith),
    )
  }

  async generateEncryptedKeyPair(
    keyToEncryptWith: VaultKey,
  ): Promise<{ publicKey: VaultKey; encryptedPrivateKey: string }> {
    const keyPair = await VaultCryptoGenerationService.generateKeyPair()

    return {
      publicKey: keyPair.publicKey,
      encryptedPrivateKey: await this.encryptKey(keyPair.privateKey, keyToEncryptWith),
    }
  }
}

export const VaultKeyManagementService: VaultKeyManagementService = new DefaultVaultKeyManagementService()
