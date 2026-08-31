import { describe, expect, it, vi } from 'vitest'
import { concatBuffers, decodeUtf8, encodeHex, toArrayBuffer, toUint8Array } from '../src'

describe('toUint8Array', () => {
  it('encodes strings as UTF-8', () => {
    expect(toUint8Array('Crittografia 🔐')).toEqual(
      new TextEncoder().encode('Crittografia 🔐'),
    )
  })

  it('copies an ArrayBuffer', () => {
    const source = new Uint8Array([1, 2, 3])
    const result = toUint8Array(source.buffer)

    source[0] = 9

    expect(result).toEqual(new Uint8Array([1, 2, 3]))
  })

  it('supports environments without SharedArrayBuffer', () => {
    vi.stubGlobal('SharedArrayBuffer', undefined)

    try {
      expect(toUint8Array(new Uint8Array([1, 2, 3]).buffer)).toEqual(
        new Uint8Array([1, 2, 3]),
      )
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('copies only the bytes represented by an offset view', () => {
    const source = new Uint8Array([99, 1, 2, 3, 99])
    const view = new Uint8Array(source.buffer, 1, 3)
    const result = toUint8Array(view)

    source[2] = 9

    expect(result).toEqual(new Uint8Array([1, 2, 3]))
  })

  it('supports non-Uint8Array views', () => {
    const source = new Uint8Array([99, 1, 2, 3, 99])
    const view = new DataView(source.buffer, 1, 3)

    expect(toUint8Array(view)).toEqual(new Uint8Array([1, 2, 3]))
  })

  it('returns an empty array for empty input', () => {
    expect(toUint8Array(new ArrayBuffer(0))).toEqual(new Uint8Array())
  })
})

describe('toArrayBuffer', () => {
  it('copies an ArrayBuffer', () => {
    const source = new Uint8Array([1, 2, 3])
    const result = toArrayBuffer(source.buffer)

    source[0] = 9

    expect(new Uint8Array(result)).toEqual(new Uint8Array([1, 2, 3]))
  })

  it('copies only the bytes represented by an offset view', () => {
    const source = new Uint8Array([99, 1, 2, 3, 99])
    const view = new Uint8Array(source.buffer, 1, 3)
    const result = toArrayBuffer(view)

    source[2] = 9

    expect(new Uint8Array(result)).toEqual(new Uint8Array([1, 2, 3]))
    expect(result.byteLength).toBe(3)
  })

  it('returns an empty buffer for empty input', () => {
    expect(toArrayBuffer(new Uint8Array()).byteLength).toBe(0)
  })
})

describe('concatBuffers', () => {
  it('concatenates mixed binary inputs in order', () => {
    const first = new Uint8Array([1, 2])
    const second = new Uint8Array([3, 4]).buffer
    const third = new DataView(new Uint8Array([5, 6]).buffer)

    expect(concatBuffers(first, second, third)).toEqual(
      new Uint8Array([1, 2, 3, 4, 5, 6]),
    )
  })

  it('uses only the bytes represented by offset views', () => {
    const source = new Uint8Array([99, 1, 2, 3, 99])
    const view = new Uint8Array(source.buffer, 1, 3)

    expect(concatBuffers(new Uint8Array([0]), view)).toEqual(
      new Uint8Array([0, 1, 2, 3]),
    )
  })

  it('does not share storage with its inputs', () => {
    const first = new Uint8Array([1, 2])
    const second = new Uint8Array([3, 4])
    const result = concatBuffers(first, second)

    first[0] = 9
    second[0] = 8
    result[1] = 7

    expect(result).toEqual(new Uint8Array([1, 7, 3, 4]))
    expect(first).toEqual(new Uint8Array([9, 2]))
    expect(second).toEqual(new Uint8Array([8, 4]))
  })

  it('returns an empty array when called without inputs', () => {
    expect(concatBuffers()).toEqual(new Uint8Array())
  })
})

describe('encodeHex', () => {
  it('encodes every byte with two lowercase hexadecimal digits', () => {
    expect(encodeHex(new Uint8Array([0, 15, 16, 255]))).toBe('000f10ff')
  })

  it('encodes empty input', () => {
    expect(encodeHex(new Uint8Array())).toBe('')
  })
})

describe('decodeUtf8', () => {
  it('decodes UTF-8 bytes', () => {
    expect(decodeUtf8(new TextEncoder().encode('Crittografia 🔐'))).toBe('Crittografia 🔐')
  })
})
