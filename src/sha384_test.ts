import { assertEquals } from "https://deno.land/std@0.52.0/testing/asserts.ts";

import { Sha384 } from "./sha384.ts";
import { stringToBytes } from "./utils.ts";

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA384.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA2_Additional.pdf
const TEST_CASES: Array<[string, Uint8Array]> = [
  [
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    stringToBytes("abc"),
  ],
  [
    "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
    stringToBytes(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    ),
  ],
  [
    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    new Uint8Array(),
  ],
  [
    "435770712c611be7293a66dd0dc8d1450dc7ff7337bfe115bf058ef2eb9bed09cee85c26963a5bcc0905dc2df7cc6a76",
    new Uint8Array(111),
  ],
  [
    "3e0cbf3aee0e3aa70415beae1bd12dd7db821efa446440f12132edffce76f635e53526a111491e75ee8e27b9700eec20",
    new Uint8Array(112),
  ],
  [
    "6be9af2cf3cd5dd12c8d9399ec2b34e66034fbd699d4e0221d39074172a380656089caafe8f39963f94cc7c0a07e3d21",
    new Uint8Array(113),
  ],
  [
    "12a72ae4972776b0db7d73d160a15ef0d19645ec96c7f816411ab780c794aa496a22909d941fe671ed3f3caee900bdd5",
    new Uint8Array(122),
  ],
  [
    "aae017d4ae5b6346dd60a19d52130fb55194b6327dd40b89c11efc8222292de81e1a23c9b59f9f58b7f6ad463fa108ca",
    new Uint8Array(1000),
  ],
  [
    "7df01148677b7f18617eee3a23104f0eed6bb8c90a6046f715c9445ff43c30d69e9e7082de39c3452fd1d3afd9ba0689",
    new Uint8Array(1000).fill(0x41),
  ],
  [
    "1bb8e256da4a0d1e87453528254f223b4cb7e49c4420dbfa766bba4adba44eeca392ff6a9f565bc347158cc970ce44ec",
    new Uint8Array(1005).fill(0x55),
  ],
  [
    "8a1979f9049b3fff15ea3a43a4cf84c634fd14acad1c333fecb72c588b68868b66a994386dc0cd1687b9ee2e34983b81",
    new Uint8Array(1000000),
  ],
];

Deno.test("SHA-384", () => {
  for (let i = 0; i < TEST_CASES.length; i++) {
    assertEquals(
      new Sha384().hashToLowerHex(TEST_CASES[i][1]),
      TEST_CASES[i][0],
    );
  }
});
