import { describe, expect, it } from 'vitest'
import { encodeHex, HKDFKeyLength, randomUUID, SHAAlgorithm, VaultCryptoAlgorithmService, VaultKey } from '../src'

const importHmacKey = async (key: Uint8Array<ArrayBuffer>): Promise<VaultKey> => {
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: SHAAlgorithm.SHA256 },
    true,
    ['sign'],
  )

  return new VaultKey(cryptoKey, 'test-key')
}

describe('VaultCryptoAlgorithmService', () => {
  it.each([
    [
      SHAAlgorithm.SHA256,
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    ],
    [
      SHAAlgorithm.SHA384,
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
    ],
    [
      SHAAlgorithm.SHA512,
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    ],
  ])('hashes UTF-8 input with %s', (hashAlgorithm, expected) => {
    const hash = VaultCryptoAlgorithmService.SHA({
      message: 'abc',
      hash: hashAlgorithm,
    })

    expect(encodeHex(hash)).toBe(expected)
  })

  it('derives a PBKDF2 key matching the published test vector', async () => {
    const key = await VaultCryptoAlgorithmService.PBKDF2({
      password: 'password',
      salt: 'salt',
      iterations: 2,
      hash: SHAAlgorithm.SHA256,
    })

    expect(encodeHex(await key.getKeyBuffer())).toBe(
      'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43',
    )
  })

  it('derives an HKDF key with the default and explicit key length', async () => {
    const masterKey = await importHmacKey(new Uint8Array(22).fill(0x0b))
    const params = {
      masterKey,
      salt: Uint8Array.from({ length: 13 }, (_, index) => index),
      info: Uint8Array.from({ length: 10 }, (_, index) => 0xf0 + index),
      hash: SHAAlgorithm.SHA256,
    }
    const defaultLengthKey = await VaultCryptoAlgorithmService.HKDF(params)
    const explicitLengthKey = await VaultCryptoAlgorithmService.HKDF({
      ...params,
      keyLength: HKDFKeyLength[256],
    })

    expect(encodeHex(await defaultLengthKey.getKeyBuffer())).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf',
    )
    expect(await explicitLengthKey.getKeyBuffer()).toEqual(await defaultLengthKey.getKeyBuffer())
  })

  it('calculates an HMAC matching the published test vector', async () => {
    const key = await importHmacKey(new Uint8Array(20).fill(0x0b))
    const hmac = await VaultCryptoAlgorithmService.HMAC({
      key,
      message: 'Hi There',
      hash: SHAAlgorithm.SHA256,
    })

    expect(encodeHex(hmac)).toBe(
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    )
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
