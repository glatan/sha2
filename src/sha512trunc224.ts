import { Word64 } from "./mod.ts";

// deno-fmt-ignore
export class Sha512Trunc224 extends Word64 {
  constructor() {
    super(
      BigUint64Array.from([
        0x8C3D_37C8_1954_4DA2n, 0x73E1_9966_89DC_D4D6n, 0x1DFA_B7AE_32FF_9C82n, 0x679D_D514_582F_9FCFn,
        0x0F6D_2B69_7BD4_4DA8n, 0x77E3_6F73_04C4_8942n, 0x3F9D_85A8_6A1D_36C8n, 0x1112_E6AD_91D6_92A1n,
      ]),
    );
  }
  hashToBytes(message: Uint8Array): Uint8Array {
    return super.hashToBytes(message).slice(0, 28);
  }
}
