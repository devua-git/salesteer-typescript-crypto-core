export type ArrayBufferInput = ArrayBuffer | ArrayBufferView

export function toUint8Array(input: Uint8Array<ArrayBuffer> | ArrayBufferInput | string): Uint8Array<ArrayBuffer> {
  if (typeof input === 'string') {
    return new TextEncoder().encode(input)
  }

  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength).slice()
  }

  return new Uint8Array(input).slice()
}

export function toArrayBuffer(input: ArrayBufferInput): ArrayBuffer {
  return toUint8Array(input).buffer
}

export const concatBuffers = (...inputs: readonly ArrayBufferInput[]): Uint8Array<ArrayBuffer> => {
  const byteArrays = inputs.map(toUint8Array)
  const totalLength = byteArrays.reduce((length, bytes) => length + bytes.byteLength, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0

  for (const bytes of byteArrays) {
    result.set(bytes, offset)
    offset += bytes.byteLength
  }

  return result
}

export const encodeHex = (input: ArrayBufferInput): string => {
  return Array.from(
    toUint8Array(input),
    byte => byte.toString(16).padStart(2, '0'),
  ).join('')
}

export const decodeUtf8 = (input: ArrayBufferInput): string => {
  return new TextDecoder().decode(toUint8Array(input))
}
