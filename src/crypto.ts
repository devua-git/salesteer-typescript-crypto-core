import { decode as cborDecode, encode as cborEncode } from 'cbor2'
import { decodeBase64, encodeBase64 } from './base64'
import { toArrayBuffer } from './bytes'
import { VaultCryptoGenerationService } from './generation'
import { VaultKey } from './key'

type AlgorithmParams = {
  name: string
  iv?: Uint8Array<ArrayBuffer>
}

type VaultEncryptedPayload = {
  recipients: {
    kid: string
    encryptedCEK: Uint8Array<ArrayBuffer>
    algorithm: AlgorithmParams
  }[]
  algorithm: AlgorithmParams
  ciphertext: Uint8Array<ArrayBuffer>
}

type RecipientAAD = {
  kid: string
  algorithm: AlgorithmParams
}

export interface VaultCryptoService {
  encrypt(payload: Uint8Array<ArrayBuffer>, key: VaultKey): Promise<string>
  decrypt(payload: string, key: VaultKey): Promise<Uint8Array<ArrayBuffer>>
  addRecipientKey(payload: string, key: VaultKey, recipientKey: VaultKey): Promise<string>
}

class DefaultVaultCryptoService implements VaultCryptoService {
  private makeRecipientAAD(recipientKey: VaultKey): RecipientAAD {
    return {
      kid: recipientKey.kid,
      algorithm: {
        name: recipientKey.key.algorithm.name,
        iv: recipientKey.key.algorithm.name === 'RSA-OAEP'
          ? undefined
          : VaultCryptoGenerationService.generateIv(),
      },
    }
  }

  private makeRecipientAlgorithmParams(recipientAAD: RecipientAAD): AlgorithmIdentifier {
    if (recipientAAD.algorithm.name !== 'AES-GCM') {
      return { name: recipientAAD.algorithm.name }
    }

    const iv = recipientAAD.algorithm.iv
    if (iv === undefined) {
      throw new Error('Missing recipient IV')
    }

    return {
      name: recipientAAD.algorithm.name,
      iv: toArrayBuffer(iv),
      additionalData: toArrayBuffer(cborEncode({
        kid: recipientAAD.kid,
        algorithm: recipientAAD.algorithm,
      })),
    } as AesGcmParams
  }

  private async encryptCEK(
    contentEncryptionKey: VaultKey,
    recipientKey: VaultKey,
    recipientAAD: RecipientAAD,
  ): Promise<ArrayBuffer> {
    return globalThis.crypto.subtle.encrypt(
      this.makeRecipientAlgorithmParams(recipientAAD),
      recipientKey.key,
      toArrayBuffer(await contentEncryptionKey.getKeyBuffer()),
    )
  }

  private async makeEncryptedRecipient(
    recipientAAD: RecipientAAD,
    contentEncryptionKey: VaultKey,
    recipientKey: VaultKey,
  ): Promise<VaultEncryptedPayload['recipients'][number]> {
    return {
      kid: recipientKey.kid,
      algorithm: recipientAAD.algorithm,
      encryptedCEK: new Uint8Array(
        await this.encryptCEK(contentEncryptionKey, recipientKey, recipientAAD),
      ),
    }
  }

  private makePayloadAlgorithmParams(payloadIv: Uint8Array<ArrayBuffer>): AesGcmParams {
    return {
      name: 'AES-GCM',
      iv: toArrayBuffer(payloadIv),
      additionalData: toArrayBuffer(cborEncode({
        algorithm: {
          name: 'AES-GCM',
          iv: payloadIv,
        },
      })),
    }
  }

  private async encryptPayload(
    payload: Uint8Array<ArrayBuffer>,
    payloadIv: Uint8Array<ArrayBuffer>,
    contentEncryptionKey: VaultKey,
  ): Promise<Uint8Array<ArrayBuffer>> {
    const encryptedPayload = await globalThis.crypto.subtle.encrypt(
      this.makePayloadAlgorithmParams(payloadIv),
      contentEncryptionKey.key,
      toArrayBuffer(payload),
    )

    return new Uint8Array(encryptedPayload)
  }

  async encrypt(payload: Uint8Array<ArrayBuffer>, recipientKey: VaultKey): Promise<string> {
    const contentEncryptionKey = await VaultCryptoGenerationService.generateSymmetricKey()
    const recipientAAD = this.makeRecipientAAD(recipientKey)
    const recipient = await this.makeEncryptedRecipient(
      recipientAAD,
      contentEncryptionKey,
      recipientKey,
    )
    const payloadIv = VaultCryptoGenerationService.generateIv()
    const encryptedPayload: VaultEncryptedPayload = {
      algorithm: {
        name: 'AES-GCM',
        iv: payloadIv,
      },
      recipients: [recipient],
      ciphertext: await this.encryptPayload(payload, payloadIv, contentEncryptionKey),
    }

    return encodeBase64(cborEncode(encryptedPayload))
  }

  private decodePayload(payload: string): VaultEncryptedPayload {
    return cborDecode<VaultEncryptedPayload>(decodeBase64(payload))
  }

  private async decryptCEK(
    payload: VaultEncryptedPayload,
    recipient: VaultEncryptedPayload['recipients'][number],
    key: VaultKey,
  ): Promise<VaultKey> {
    const decryptedKey = await globalThis.crypto.subtle.decrypt(
      this.makeRecipientAlgorithmParams(recipient),
      key.key,
      toArrayBuffer(recipient.encryptedCEK),
    )
    const contentEncryptionKey = await globalThis.crypto.subtle.importKey(
      'raw',
      decryptedKey,
      payload.algorithm.name,
      true,
      ['encrypt', 'decrypt'],
    )

    return new VaultKey(contentEncryptionKey, VaultCryptoGenerationService.UUID())
  }

  private async decryptPayload(
    payload: VaultEncryptedPayload,
    contentEncryptionKey: VaultKey,
  ): Promise<Uint8Array<ArrayBuffer>> {
    const payloadIv = payload.algorithm.iv
    if (payloadIv === undefined) {
      throw new Error('Missing payload IV')
    }

    const decryptedPayload = await globalThis.crypto.subtle.decrypt(
      this.makePayloadAlgorithmParams(payloadIv),
      contentEncryptionKey.key,
      toArrayBuffer(payload.ciphertext),
    )

    return new Uint8Array(decryptedPayload)
  }

  async decrypt(payload: string, key: VaultKey): Promise<Uint8Array<ArrayBuffer>> {
    const decodedPayload = this.decodePayload(payload)
    const recipient = decodedPayload.recipients.find(({ kid }) => kid === key.kid)

    if (recipient === undefined) {
      throw new Error('Recipient not found')
    }

    return this.decryptPayload(
      decodedPayload,
      await this.decryptCEK(decodedPayload, recipient, key),
    )
  }

  async addRecipientKey(
    payload: string,
    unlockKey: VaultKey,
    recipientKey: VaultKey,
  ): Promise<string> {
    const decodedPayload = this.decodePayload(payload)
    const recipient = decodedPayload.recipients.find(({ kid }) => kid === unlockKey.kid)

    if (recipient === undefined) {
      throw new Error('Recipient not found')
    }

    const contentEncryptionKey = await this.decryptCEK(decodedPayload, recipient, unlockKey)
    await this.decryptPayload(decodedPayload, contentEncryptionKey)

    const newRecipient = await this.makeEncryptedRecipient(
      this.makeRecipientAAD(recipientKey),
      contentEncryptionKey,
      recipientKey,
    )

    return encodeBase64(cborEncode(
      {
        ...decodedPayload,
        recipients: [
          ...decodedPayload.recipients.filter(({ kid }) => kid !== recipientKey.kid),
          newRecipient,
        ],
      } satisfies VaultEncryptedPayload,
    ))
  }
}

export const VaultCryptoService: VaultCryptoService = new DefaultVaultCryptoService()
