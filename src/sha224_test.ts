import { assertEquals } from "../deps/std/asserts.ts";

import { Sha224 } from "./sha224.ts";
import { stringToBytes } from "./utils.ts";

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA224.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
const TEST_CASES: Array<[string, Uint8Array]> = [
  [
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    stringToBytes("abc"),
  ],
  [
    "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3",
    stringToBytes(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    ),
  ],
  [
    "e33f9d75e6ae1369dbabf81b96b4591ae46bba30b591a6b6c62542b5",
    Uint8Array.from([0xFF]),
  ],
  [
    "fd19e74690d291467ce59f077df311638f1c3a46e510d0e49a67062d",
    Uint8Array.from([0xe5, 0xe0, 0x99, 0x24]),
  ],
  [
    "5c3e25b69d0ea26f260cfae87e23759e1eca9d1ecc9fbf3c62266804",
    new Uint8Array(56),
  ],
  [
    "3706197f66890a41779dc8791670522e136fafa24874685715bd0a8a",
    new Uint8Array(1000).fill(0x51),
  ],
  [
    "a8d0c66b5c6fdfd836eb3c6d04d32dfe66c3b1f168b488bf4c9c66ce",
    new Uint8Array(1000).fill(0x41),
  ],
  [
    "cb00ecd03788bf6c0908401e0eb053ac61f35e7e20a2cfd7bd96d640",
    new Uint8Array(1005).fill(0x99),
  ],
  [
    "3a5d74b68f14f3a4b2be9289b8d370672d0b3d2f53bc303c59032df3",
    new Uint8Array(1000000),
  ],
];

Deno.test("SHA-224", () => {
  for (let i = 0; i < TEST_CASES.length; i++) {
    assertEquals(
      new Sha224().hashToLowerHex(TEST_CASES[i][1]),
      TEST_CASES[i][0],
    );
  }
});
