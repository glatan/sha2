import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

import { Sha512Trunc224 } from "./sha512trunc224.ts";
import { stringToBytes } from "./utils.ts";

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
const TEST_CASES: Array<[string, Uint8Array]> = [
  [
    "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
    stringToBytes("abc"),
  ],
  [
    "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
    stringToBytes(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    ),
  ],
];

Deno.test("SHA-512Trunc224", () => {
  for (let i = 0; i < TEST_CASES.length; i++) {
    assertEquals(
      new Sha512Trunc224().hashToLowerHex(TEST_CASES[i][1]),
      TEST_CASES[i][0],
    );
  }
});
