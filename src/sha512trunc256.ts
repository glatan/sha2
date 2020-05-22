import { Word64 } from "./mod.ts";

// deno-fmt-ignore
export class Sha512Trunc256 extends Word64 {
  constructor() {
    super(
      BigUint64Array.from([
        0x2231_2194_FC2B_F72Cn, 0x9F55_5FA3_C84C_64C2n, 0x2393_B86B_6F53_B151n, 0x9638_7719_5940_EABDn,
        0x9628_3EE2_A88E_FFE3n, 0xBE5E_1E25_5386_3992n, 0x2B01_99FC_2C85_B8AAn, 0x0EB7_2DDC_81C5_2CA2n,
      ]),
    );
  }
  hashToBytes(message: Uint8Array): Uint8Array {
    return super.hashToBytes(message).slice(0, 32);
  }
}
