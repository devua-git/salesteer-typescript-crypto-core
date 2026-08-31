import { decode as cborDecode, encode as cborEncode } from 'cbor2'
import { describe, expect, it } from 'vitest'
import { decodeBase64, encodeBase64, VaultCryptoGenerationService, VaultCryptoService } from '../src'

const message = new TextEncoder().encode('Salesteer vault payload')

type TestEncryptedPayload = {
  recipients: {
    kid: string
    encryptedCEK: Uint8Array
    algorithm: { name: string; iv?: Uint8Array }
  }[]
  algorithm: { name: string; iv?: Uint8Array }
  ciphertext: Uint8Array
}

const mutateEncryptedPayload = (
  encrypted: string,
  mutate: (payload: TestEncryptedPayload) => void,
): string => {
  const payload = cborDecode<TestEncryptedPayload>(decodeBase64(encrypted))
  mutate(payload)

  return encodeBase64(cborEncode(payload))
}

describe('VaultCryptoService', () => {
  it('encrypts and decrypts a payload for its recipient', async () => {
    const recipientKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const encrypted = await VaultCryptoService.encrypt(message, recipientKey)

    await expect(VaultCryptoService.decrypt(encrypted, recipientKey)).resolves.toEqual(message)
  })

  it('rejects keys that are not payload recipients', async () => {
    const recipientKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const unrelatedKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const encrypted = await VaultCryptoService.encrypt(message, recipientKey)

    await expect(VaultCryptoService.decrypt(encrypted, unrelatedKey)).rejects.toThrow(
      'Recipient not found',
    )
  })

  it('rejects a recipient without an IV', async () => {
    const recipientKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const encrypted = await VaultCryptoService.encrypt(message, recipientKey)
    const malformed = mutateEncryptedPayload(encrypted, (payload) => {
      const recipient = payload.recipients[0]
      if (recipient === undefined) {
        throw new Error('Missing test recipient')
      }

      delete recipient.algorithm.iv
    })

    await expect(VaultCryptoService.decrypt(malformed, recipientKey)).rejects.toThrow(
      'Missing recipient IV',
    )
  })

  it('rejects a payload without an IV', async () => {
    const recipientKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const encrypted = await VaultCryptoService.encrypt(message, recipientKey)
    const malformed = mutateEncryptedPayload(encrypted, (payload) => {
      delete payload.algorithm.iv
    })

    await expect(VaultCryptoService.decrypt(malformed, recipientKey)).rejects.toThrow(
      'Missing payload IV',
    )
  })

  it('adds a recipient without removing the existing recipient', async () => {
    const originalRecipient = await VaultCryptoGenerationService.generateSymmetricKey()
    const additionalRecipient = await VaultCryptoGenerationService.generateSymmetricKey()
    const encrypted = await VaultCryptoService.encrypt(message, originalRecipient)
    const shared = await VaultCryptoService.addRecipientKey(
      encrypted,
      originalRecipient,
      additionalRecipient,
    )

    await expect(VaultCryptoService.decrypt(shared, originalRecipient)).resolves.toEqual(message)
    await expect(VaultCryptoService.decrypt(shared, additionalRecipient)).resolves.toEqual(message)
  })

  it('replaces an existing recipient with the same key id', async () => {
    const originalRecipient = await VaultCryptoGenerationService.generateSymmetricKey()
    const replacementRecipient = await VaultCryptoGenerationService.generateSymmetricKey()
    replacementRecipient.kid = originalRecipient.kid
    const encrypted = await VaultCryptoService.encrypt(message, originalRecipient)
    const replaced = await VaultCryptoService.addRecipientKey(
      encrypted,
      originalRecipient,
      replacementRecipient,
    )

    await expect(VaultCryptoService.decrypt(replaced, replacementRecipient)).resolves.toEqual(message)
    await expect(VaultCryptoService.decrypt(replaced, originalRecipient)).rejects.toThrow()
  })

  it('rejects adding a recipient with an unrelated unlock key', async () => {
    const recipientKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const unrelatedKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const additionalRecipient = await VaultCryptoGenerationService.generateSymmetricKey()
    const encrypted = await VaultCryptoService.encrypt(message, recipientKey)

    await expect(
      VaultCryptoService.addRecipientKey(encrypted, unrelatedKey, additionalRecipient),
    ).rejects.toThrow('Recipient not found')
  })
})
