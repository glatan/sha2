import { assertEquals } from "https://deno.land/std/testing/asserts.ts";
import { Sha512Trunc224 } from "./sha512trunc224.ts";

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
// deno-fmt-ignore
const TEST_CASES: Array<[string, Uint8Array]> = [
  // abc
  [
    "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
    Uint8Array.from([0x61, 0x62, 0x63]),
  ],
  // abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu
  [
    "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
    Uint8Array.from([
      0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
      0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
      0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
      0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
      0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C,
      0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
      0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
      0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
      0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
      0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71,
      0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
      0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73,
      0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74,
      0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75
    ])
  ],
];

Deno.test("SHA-512Trunc224", () => {
  for (let i = 0; i < TEST_CASES.length; i++) {
    assertEquals(
      new Sha512Trunc224(TEST_CASES[i][1]).hashToLowerHex(),
      TEST_CASES[i][0],
    );
  }
});
