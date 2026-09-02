import { describe, expect, it } from 'vitest'
import { VaultCryptoGenerationService, VaultCryptoService, VaultKeyManagementService } from '../src'

const message = new TextEncoder().encode('Salesteer managed key payload')

describe('VaultKeyManagementService', () => {
  it('derives deterministic and distinct master keys', async () => {
    const first = await VaultKeyManagementService.deriveMasterKey('password', 'salt', 2)
    const second = await VaultKeyManagementService.deriveMasterKey('password', 'salt', 2)

    expect(await first.masterKey.getKeyBuffer()).toEqual(await second.masterKey.getKeyBuffer())
    expect(await first.streatchedMasterKey.getKeyBuffer()).toEqual(
      await second.streatchedMasterKey.getKeyBuffer(),
    )
    expect(await first.streatchedMasterKey.getKeyBuffer()).not.toEqual(
      await first.masterKey.getKeyBuffer(),
    )
  })

  it('hashes a master password deterministically', async () => {
    const { masterKey } = await VaultKeyManagementService.deriveMasterKey('password', 'salt', 2)

    await expect(
      VaultKeyManagementService.hashMasterPassword(masterKey, 'password', 2),
    ).resolves.toBe('4a82EQAeBd0Lq1bqWGKvZH/oMgM0Xz/Feb5VkQV+6OI=')
  })

  it('encrypts and restores a key', async () => {
    const wrappingKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const originalKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const encryptedKey = await VaultKeyManagementService.encryptKey(originalKey, wrappingKey)
    const restoredKey = await VaultKeyManagementService.decryptKey(encryptedKey, wrappingKey)

    expect(restoredKey.kid).toBe(originalKey.kid)
    expect(restoredKey.key.algorithm).toEqual(originalKey.key.algorithm)
    expect(restoredKey.key.usages).toEqual(originalKey.key.usages)
    expect(await restoredKey.getKeyBuffer()).toEqual(await originalKey.getKeyBuffer())
  })

  it('generates an encrypted RSA key pair usable for asymmetric encryption', async () => {
    const wrappingKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const { publicKey, encryptedPrivateKey } = await VaultKeyManagementService
      .generateEncryptedKeyPair(wrappingKey)
    const privateKey = await VaultKeyManagementService.decryptKey(encryptedPrivateKey, wrappingKey)
    const encryptedMessage = await VaultCryptoService.encrypt(message, publicKey)

    expect(privateKey.kid).toBe(publicKey.kid)
    expect(publicKey.key.type).toBe('public')
    expect(privateKey.key.type).toBe('private')
    await expect(VaultCryptoService.decrypt(encryptedMessage, privateKey)).resolves.toEqual(message)
  })
})
