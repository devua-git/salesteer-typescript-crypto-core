import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import {
  encodeBase64,
  VaultCryptoGenerationService,
  type VaultKey,
  VaultKeyManagementService,
  VaultService,
} from '../src'

describe('VaultService', () => {
  let rsaKeyPair!: { publicKey: VaultKey; privateKey: VaultKey }

  beforeAll(async () => {
    rsaKeyPair = await VaultCryptoGenerationService.generateKeyPair()
    vi.spyOn(VaultCryptoGenerationService, 'generateKeyPair').mockResolvedValue(rsaKeyPair)
  })

  afterAll(() => {
    vi.restoreAllMocks()
  })

  it('derives stable master password data for the same user', async () => {
    const first = await VaultService.deriveMasterPassword(
      'master-password',
      42,
      'user@example.com',
      2,
    )
    const second = await VaultService.deriveMasterPassword(
      'master-password',
      42,
      'user@example.com',
      2,
    )

    expect(first.hashedPassword).toBe(second.hashedPassword)
    expect(first.streatchedMasterKey.kid).toBe(second.streatchedMasterKey.kid)
    expect(await first.streatchedMasterKey.getKeyBuffer()).toEqual(
      await second.streatchedMasterKey.getKeyBuffer(),
    )
  })

  it('unlocks a personal vault without a tenant key', async () => {
    const unlockKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const symmetricKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const encryptedSymmetricKey = await VaultKeyManagementService.encryptKey(
      symmetricKey,
      unlockKey,
    )
    const keys = await VaultService.unlockVaultKeys({
      unlockKey,
      token: {
        vault_encrypted_symmetric_key: encryptedSymmetricKey,
        tenant_encrypted_symmetric_key: null,
        tenant_rsa_encrypted_private_key: '',
      },
    })

    expect(keys.tenantSymmetricKey).toBeNull()
    expect(await keys.symmetricKey.getKeyBuffer()).toEqual(await symmetricKey.getKeyBuffer())
  })

  it('sets up a personal vault without a tenant key', async () => {
    const setup = await VaultService.firstSetup('master-password', {
      userId: 42,
      email: 'user@example.com',
      kdfIterations: 2,
      initializeTenantVault: false,
    })

    expect(setup.hashedPassword).not.toBe('')
    expect(setup.publicKey).not.toBe('')
    expect(setup.encryptedPrivateKey).not.toBe('')
    expect(setup.encryptedSymmetricKey).not.toBe('')
    expect(setup.tenantEncryptedSymmetricKey).toBeNull()
  })

  it('sets up and unlocks a tenant vault', async () => {
    const password = 'master-password'
    const userData = {
      userId: 42,
      email: 'user@example.com',
      kdfIterations: 2,
      initializeTenantVault: true,
    }
    const setup = await VaultService.firstSetup(password, userData)
    const { streatchedMasterKey } = await VaultService.deriveMasterPassword(
      password,
      userData.userId,
      userData.email,
      userData.kdfIterations,
    )
    const keys = await VaultService.unlockVaultKeys({
      unlockKey: streatchedMasterKey,
      token: {
        vault_encrypted_symmetric_key: setup.encryptedSymmetricKey,
        tenant_encrypted_symmetric_key: setup.tenantEncryptedSymmetricKey,
        tenant_rsa_encrypted_private_key: setup.encryptedPrivateKey,
      },
    })

    expect(keys.tenantSymmetricKey).not.toBeNull()
  })

  it('prepares an invite key for an RSA recipient', async () => {
    const tenantSymmetricKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const encrypted = await VaultService.prepareInviteKey(
      encodeBase64(await rsaKeyPair.publicKey.getPayloadBuffer()),
      tenantSymmetricKey,
    )
    const decrypted = await VaultKeyManagementService.decryptKey(
      encrypted,
      rsaKeyPair.privateKey,
    )

    expect(await decrypted.getKeyBuffer()).toEqual(await tenantSymmetricKey.getKeyBuffer())
  })

  it('adds an unlock key to personal and tenant key payloads', async () => {
    const unlockKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const newUnlockKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const symmetricKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const token = {
      vault_encrypted_symmetric_key: await VaultKeyManagementService.encryptKey(
        symmetricKey,
        unlockKey,
      ),
      tenant_encrypted_symmetric_key: null,
      tenant_rsa_encrypted_private_key: await VaultKeyManagementService.encryptKey(
        rsaKeyPair.privateKey,
        unlockKey,
      ),
    }
    const updated = await VaultService.addUnlockKey(token, unlockKey, newUnlockKey)
    const decryptedSymmetricKey = await VaultKeyManagementService.decryptKey(
      updated.encryptedSymmetricKey,
      newUnlockKey,
    )
    const decryptedPrivateKey = await VaultKeyManagementService.decryptKey(
      updated.tenantRsaEncryptedPrivateKey,
      newUnlockKey,
    )

    expect(await decryptedSymmetricKey.getKeyBuffer()).toEqual(await symmetricKey.getKeyBuffer())
    expect(await decryptedPrivateKey.getKeyBuffer()).toEqual(await rsaKeyPair.privateKey.getKeyBuffer())
  })
})
