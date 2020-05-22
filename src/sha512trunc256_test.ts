import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

import { Sha512Trunc256 } from "./sha512trunc256.ts";
import { stringToBytes } from "./utils.ts";

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf
const TEST_CASES: Array<[string, Uint8Array]> = [
  [
    "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    stringToBytes("abc"),
  ],
  [
    "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
    stringToBytes(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    ),
  ],
];

Deno.test("SHA-512Trunc256", () => {
  for (let i = 0; i < TEST_CASES.length; i++) {
    assertEquals(
      new Sha512Trunc256().hashToLowerHex(TEST_CASES[i][1]),
      TEST_CASES[i][0],
    );
  }
});
