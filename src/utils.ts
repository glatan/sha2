import { sprintf } from "https://deno.land/std/fmt/mod.ts";

// Uint32
export function rotateRight(x: number, n: number): number {
  return ((x >>> (n % 32)) | (x << ((32 - n) % 32)));
}

// Uint32
export function rotateLeft(x: number, n: number): number {
  return ((x << (n % 32)) | (x >>> ((32 - n) % 32)));
}

// big endian
export function toUint32Array(bytes: Uint8Array): Uint32Array {
  let result: Uint32Array = new Uint32Array(bytes.length / 4);
  for (let i = 0; i < bytes.length / 4; i++) {
    result.set(
      Uint32Array.from([
        ((bytes[i * 4] << 24) & 0xFF00_0000) |
        ((bytes[i * 4 + 1] << 16) & 0x00FF_0000) |
        ((bytes[i * 4 + 2] << 8) & 0x0000_FF00) |
        bytes[i * 4 + 3] & 0x0000_00FF,
      ]),
      i,
    );
  }
  return result;
}

// big endian
export function toUint8Array(input: Uint32Array): Uint8Array {
  let result = new Uint8Array(input.length * 4);
  for (let i = 0; i < input.length; i++) {
    result.set(
      Uint8Array.from([
        (input[i] >>> 24) & 0xFF,
        (input[i] >>> 16) & 0xFF,
        (input[i] >>> 8) & 0xFF,
        input[i] & 0xFF,
      ]),
      i * 4,
    );
  }
  return result;
}

export function bytesToLowerHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += sprintf("%02x", byte);
  }
  return hex;
}

export function stringToBytes(str: string): Uint8Array {
  let bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    bytes.set(Uint8Array.of(str.charCodeAt(i)), i);
  }
  return Uint8Array.from(bytes);
}
