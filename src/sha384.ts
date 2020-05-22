import { Word64 } from "./mod.ts";

// deno-fmt-ignore
export class Sha384 extends Word64 {
  constructor() {
    super(
      BigUint64Array.from([
        0xCBBB_9D5D_C105_9ED8n, 0x629A_292A_367C_D507n, 0x9159_015A_3070_DD17n, 0x152F_ECD8_F70E_5939n,
        0x6733_2667_FFC0_0B31n, 0x8EB4_4A87_6858_1511n, 0xDB0C_2E0D_64F9_8FA7n, 0x47B5_481D_BEFA_4FA4n,
      ]),
    );
  }
  hashToBytes(message: Uint8Array): Uint8Array {
    return super.hashToBytes(message).slice(0, 48);
  }
}
