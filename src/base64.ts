import { type ArrayBufferInput, toUint8Array } from './bytes'

const base64Pattern = /^[A-Za-z0-9+/]*={0,2}$/
const base64UrlPattern = /^[A-Za-z0-9_-]*={0,2}$/
const chunkSize = 0x8000

const validateBase64 = (value: string, pattern: RegExp): string => {
  if (!pattern.test(value)) {
    throw new TypeError('Invalid Base64 input')
  }

  const paddingIndex = value.indexOf('=')
  const unpadded = paddingIndex === -1 ? value : value.slice(0, paddingIndex)
  const paddingLength = value.length - unpadded.length

  if (unpadded.length % 4 === 1 || (paddingLength > 0 && value.length % 4 !== 0)) {
    throw new TypeError('Invalid Base64 input')
  }

  return unpadded.padEnd(unpadded.length + ((4 - (unpadded.length % 4)) % 4), '=')
}

export const encodeBase64 = (input: ArrayBufferInput): string => {
  const bytes = toUint8Array(input)
  let binary = ''

  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize))
  }

  return btoa(binary)
}

export const decodeBase64 = (value: string): Uint8Array<ArrayBuffer> => {
  const binary = atob(validateBase64(value, base64Pattern))
  const bytes = new Uint8Array(binary.length)

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }

  return bytes
}

export const encodeBase64Url = (input: ArrayBufferInput): string => {
  return encodeBase64(input).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

export const decodeBase64Url = (value: string): Uint8Array<ArrayBuffer> => {
  const base64 = validateBase64(value, base64UrlPattern)
    .replaceAll('-', '+')
    .replaceAll('_', '/')

  return decodeBase64(base64)
}
