import { describe, expect, it } from 'vitest'
import { decodeBase64, decodeBase64Url, encodeBase64, encodeBase64Url } from '../src'

describe('Base64 encoding', () => {
  it.each([
    [new Uint8Array(), ''],
    [new TextEncoder().encode('f'), 'Zg=='],
    [new TextEncoder().encode('fo'), 'Zm8='],
    [new TextEncoder().encode('foo'), 'Zm9v'],
    [new Uint8Array([251, 255, 239]), '+//v'],
  ])('encodes %j as %s', (input, expected) => {
    expect(encodeBase64(input)).toBe(expected)
  })

  it('encodes ArrayBuffer input', () => {
    const input = new TextEncoder().encode('Hello').buffer

    expect(encodeBase64(input)).toBe('SGVsbG8=')
  })

  it('encodes only the bytes represented by an offset view', () => {
    const input = new TextEncoder().encode('xHello!')
    const view = new Uint8Array(input.buffer, 1, 5)

    expect(encodeBase64(view)).toBe('SGVsbG8=')
  })

  it('round-trips arbitrary binary data', () => {
    const input = Uint8Array.from({ length: 256 }, (_, index) => index)

    expect(decodeBase64(encodeBase64(input))).toEqual(input)
  })

  it('encodes inputs larger than one processing chunk', () => {
    const input = new Uint8Array(0x8001).fill(255)

    expect(decodeBase64(encodeBase64(input))).toEqual(input)
  })

  it.each([
    ['Zg==', 'f'],
    ['Zg', 'f'],
    ['Zm8=', 'fo'],
    ['Zm8', 'fo'],
    ['Zm9v', 'foo'],
  ])('decodes valid padded or unpadded input %j', (input, expected) => {
    expect(new TextDecoder().decode(decodeBase64(input))).toBe(expected)
  })

  it.each([
    'A',
    'ab=c',
    'abc===',
    'abc!',
    'SGVsbG8==',
    ' SGVsbG8=',
    'SGVsbG8= ',
    'SGVs\nbG8=',
  ])(
    'rejects malformed input %j',
    (value) => {
      expect(() => decodeBase64(value)).toThrow(TypeError)
    },
  )
})

describe('Base64URL encoding', () => {
  it.each([
    [new Uint8Array(), ''],
    [new TextEncoder().encode('f'), 'Zg'],
    [new TextEncoder().encode('fo'), 'Zm8'],
    [new TextEncoder().encode('foo'), 'Zm9v'],
    [new Uint8Array([251, 255, 239]), '-__v'],
  ])('encodes %j as %s without padding', (input, expected) => {
    expect(encodeBase64Url(input)).toBe(expected)
  })

  it('encodes only the bytes represented by an offset view', () => {
    const source = new Uint8Array([99, 251, 255, 239, 99])
    const view = new DataView(source.buffer, 1, 3)

    expect(encodeBase64Url(view)).toBe('-__v')
  })

  it('round-trips arbitrary binary data', () => {
    const input = Uint8Array.from({ length: 256 }, (_, index) => index)

    expect(decodeBase64Url(encodeBase64Url(input))).toEqual(input)
  })

  it.each([
    ['Zg==', 'f'],
    ['Zg', 'f'],
    ['Zm8=', 'fo'],
    ['Zm8', 'fo'],
    ['Zm9v', 'foo'],
  ])('decodes valid padded or unpadded input %j', (input, expected) => {
    expect(new TextDecoder().decode(decodeBase64Url(input))).toBe(expected)
  })

  it.each([
    'A',
    'ab=c',
    'abc===',
    'abc+',
    'abc/',
    'SGVsbG8==',
    ' SGVsbG8=',
    'SGVsbG8= ',
    'SGVs\nbG8=',
  ])(
    'rejects malformed input %j',
    (value) => {
      expect(() => decodeBase64Url(value)).toThrow(TypeError)
    },
  )
})
