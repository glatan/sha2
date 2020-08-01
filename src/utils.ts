import { sprintf } from "../deps/std/printf.ts";

// Uint32
export function Uint32RotateRight(x: number, n: number): number {
  return ((x >>> (n % 32)) | (x << ((32 - n) % 32)));
}

// BigUint64
export function BigUint64rotateRight(x: bigint, n: bigint): bigint {
  return ((x >> (n % 64n)) | (x << ((64n - n) % 64n))) & 0xFFFF_FFFF_FFFF_FFFFn;
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
export function toBigUint64Array(bytes: Uint8Array): BigUint64Array {
  let result = new BigUint64Array(bytes.length / 8);
  for (let i = 0; i < bytes.length / 8; i++) {
    result.set(
      BigUint64Array.from([
        (BigInt(bytes[i * 8]) << 56n) & 0xFF00_0000_0000_0000n |
        (BigInt(bytes[i * 8 + 1]) << 48n) & 0x00FF_0000_0000_0000n |
        (BigInt(bytes[i * 8 + 2]) << 40n) & 0x0000_FF00_0000_0000n |
        (BigInt(bytes[i * 8 + 3]) << 32n) & 0x0000_00FF_0000_0000n |
        (BigInt(bytes[i * 8 + 4]) << 24n) & 0x0000_0000_FF00_0000n |
        (BigInt(bytes[i * 8 + 5]) << 16n) & 0x0000_0000_00FF_0000n |
        (BigInt(bytes[i * 8 + 6]) << 8n) & 0x0000_0000_0000_FF00n |
        (BigInt(bytes[i * 8 + 7])) & 0x0000_0000_0000_00FFn,
      ]),
      i,
    );
  }
  return result;
}

// big endian
export function Uint32ArrayToUint8Array(input: Uint32Array): Uint8Array {
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

export function BigUint64ArrayToUint8Array(input: BigUint64Array): Uint8Array {
  let result = new Uint8Array(input.length * 8);
  for (let i = 0; i < input.length; i++) {
    result.set(
      Uint8Array.from([
        Number((input[i] >> 56n) & 0xFFn),
        Number((input[i] >> 48n) & 0xFFn),
        Number((input[i] >> 40n) & 0xFFn),
        Number((input[i] >> 32n) & 0xFFn),
        Number((input[i] >> 24n) & 0xFFn),
        Number((input[i] >> 16n) & 0xFFn),
        Number((input[i] >> 8n) & 0xFFn),
        Number(input[i] & 0xFFn),
      ]),
      i * 8,
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
