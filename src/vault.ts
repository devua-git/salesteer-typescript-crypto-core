import { SHAAlgorithm, VaultCryptoAlgorithmService } from './algorithms'
import { decodeBase64, encodeBase64 } from './base64'
import { VaultCryptoService } from './crypto'
import { VaultCryptoGenerationService } from './generation'
import { VaultKey } from './key'
import { VaultKeyManagementService } from './key-management'

export type VaultKeyToken = {
  vault_encrypted_symmetric_key: string
  tenant_encrypted_symmetric_key: string | null
  tenant_rsa_encrypted_private_key: string
}

export type VaultSymmetricKeyPair = {
  symmetricKey: VaultKey
  tenantSymmetricKey: VaultKey | null
}

export interface VaultService {
  deriveMasterPassword(
    password: string,
    userId: number,
    email: string,
    kdfIterations: number,
  ): Promise<{ hashedPassword: string; streatchedMasterKey: VaultKey }>
  firstSetup(
    password: string,
    userData: {
      userId: number
      email: string
      kdfIterations: number
      initializeTenantVault: boolean
    },
  ): Promise<{
    hashedPassword: string
    publicKey: string
    encryptedPrivateKey: string
    encryptedSymmetricKey: string
    tenantEncryptedSymmetricKey: string | null
  }>
  unlockVaultKeys(data: {
    unlockKey: VaultKey
    token: VaultKeyToken
  }): Promise<VaultSymmetricKeyPair>
  prepareInviteKey(userPublicKey: string, tenantSymmetricKey: VaultKey): Promise<string>
  addUnlockKey(
    token: VaultKeyToken,
    unlockKey: VaultKey,
    newUnlock: VaultKey,
  ): Promise<{ encryptedSymmetricKey: string; tenantRsaEncryptedPrivateKey: string }>
}

class DefaultVaultService implements VaultService {
  async deriveMasterPassword(
    password: string,
    userId: number,
    email: string,
    kdfIterations: number,
  ): Promise<{ hashedPassword: string; streatchedMasterKey: VaultKey }> {
    const { masterKey, streatchedMasterKey } = await VaultKeyManagementService.deriveMasterKey(
      password,
      email,
      kdfIterations,
    )
    const hashedPassword = await VaultKeyManagementService.hashMasterPassword(
      masterKey,
      password,
      kdfIterations,
    )
    const keyId = VaultCryptoAlgorithmService.SHA({
      message: `${userId}-streatched-master-key`,
      hash: SHAAlgorithm.SHA256,
    })

    streatchedMasterKey.kid = Array.from(
      keyId,
      byte => byte.toString(16).padStart(2, '0'),
    ).join('')

    return { hashedPassword, streatchedMasterKey }
  }

  async firstSetup(
    password: string,
    userData: {
      userId: number
      email: string
      kdfIterations: number
      initializeTenantVault: boolean
    },
  ): Promise<{
    hashedPassword: string
    publicKey: string
    encryptedPrivateKey: string
    encryptedSymmetricKey: string
    tenantEncryptedSymmetricKey: string | null
  }> {
    const { hashedPassword, streatchedMasterKey } = await this.deriveMasterPassword(
      password,
      userData.userId,
      userData.email,
      userData.kdfIterations,
    )
    const { publicKey, encryptedPrivateKey } = await VaultKeyManagementService.generateEncryptedKeyPair(
      streatchedMasterKey,
    )
    const symmetricKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const encryptedSymmetricKey = await VaultKeyManagementService.encryptKey(
      symmetricKey,
      streatchedMasterKey,
    )
    let tenantEncryptedSymmetricKey: string | null = null

    if (userData.initializeTenantVault) {
      tenantEncryptedSymmetricKey = await VaultKeyManagementService.encryptKey(
        await VaultCryptoGenerationService.generateSymmetricKey(),
        publicKey,
      )
    }

    return {
      hashedPassword,
      publicKey: encodeBase64(await publicKey.getPayloadBuffer()),
      encryptedPrivateKey,
      encryptedSymmetricKey,
      tenantEncryptedSymmetricKey,
    }
  }

  async unlockVaultKeys(data: {
    unlockKey: VaultKey
    token: VaultKeyToken
  }): Promise<VaultSymmetricKeyPair> {
    const symmetricKey = await VaultKeyManagementService.decryptKey(
      data.token.vault_encrypted_symmetric_key,
      data.unlockKey,
    )
    let tenantSymmetricKey: VaultKey | null = null

    if (data.token.tenant_encrypted_symmetric_key) {
      const privateKey = await VaultKeyManagementService.decryptKey(
        data.token.tenant_rsa_encrypted_private_key,
        data.unlockKey,
      )
      tenantSymmetricKey = await VaultKeyManagementService.decryptKey(
        data.token.tenant_encrypted_symmetric_key,
        privateKey,
      )
    }

    return { symmetricKey, tenantSymmetricKey }
  }

  async prepareInviteKey(
    userPublicKey: string,
    tenantSymmetricKey: VaultKey,
  ): Promise<string> {
    const publicKey = await VaultKey.fromPayloadBuffer(decodeBase64(userPublicKey))

    return VaultKeyManagementService.encryptKey(tenantSymmetricKey, publicKey)
  }

  async addUnlockKey(
    token: VaultKeyToken,
    unlockKey: VaultKey,
    newUnlock: VaultKey,
  ): Promise<{ encryptedSymmetricKey: string; tenantRsaEncryptedPrivateKey: string }> {
    const encryptedSymmetricKey = await VaultCryptoService.addRecipientKey(
      token.vault_encrypted_symmetric_key,
      unlockKey,
      newUnlock,
    )
    const tenantRsaEncryptedPrivateKey = await VaultCryptoService.addRecipientKey(
      token.tenant_rsa_encrypted_private_key,
      unlockKey,
      newUnlock,
    )

    return { encryptedSymmetricKey, tenantRsaEncryptedPrivateKey }
  }
}

export const VaultService: VaultService = new DefaultVaultService()
