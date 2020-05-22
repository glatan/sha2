import { Word32 } from "./mod.ts";

// deno-fmt-ignore
export class Sha224 extends Word32 {
  constructor() {
    super(
      Uint32Array.from([
        0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0xF70E_5939,
        0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0xBEFA_4FA4,
      ]),
    );
  }
  hashToBytes(message: Uint8Array): Uint8Array {
    return super.hashToBytes(message).slice(0, 28);
  }
}
