import { describe, expect, it } from 'vitest'
import { randomUUID, SHAAlgorithm, VaultCryptoAlgorithmService, VaultKey } from '../src'

describe('VaultCryptoAlgorithmService', () => {
  it('hashes UTF-8 input with SHA-256', () => {
    const hash = VaultCryptoAlgorithmService.SHA({
      message: 'abc',
      hash: SHAAlgorithm.SHA256,
    })

    expect(Array.from(hash, byte => byte.toString(16).padStart(2, '0')).join('')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
  })

  it('derives deterministic PBKDF2 keys', async () => {
    const first = await VaultCryptoAlgorithmService.PBKDF2({
      password: 'password',
      salt: 'salt',
      iterations: 2,
      hash: SHAAlgorithm.SHA256,
    })
    const second = await VaultCryptoAlgorithmService.PBKDF2({
      password: 'password',
      salt: 'salt',
      iterations: 2,
      hash: SHAAlgorithm.SHA256,
    })

    expect(await first.getKeyBuffer()).toEqual(await second.getKeyBuffer())
  })
})

describe('randomUUID', () => {
  it('generates an RFC 4122 UUID', () => {
    expect(randomUUID()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    )
  })
})

describe('VaultKey', () => {
  it('round-trips an encoded key payload', async () => {
    const key = await globalThis.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    )
    const original = new VaultKey(key, 'key-id')
    const restored = await VaultKey.fromPayloadBuffer(await original.getPayloadBuffer())

    expect(restored.kid).toBe(original.kid)
    expect(restored.key.algorithm).toEqual(original.key.algorithm)
    expect(restored.key.usages).toEqual(original.key.usages)
    expect(await restored.getKeyBuffer()).toEqual(await original.getKeyBuffer())
    expect(await restored.getKeyBase64()).toBe(await original.getKeyBase64())
  })

  it('rejects non-extractable keys', async () => {
    const key = await globalThis.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    )

    expect(() => new VaultKey(key, 'key-id')).toThrow('Key is not extractable')
  })
})
