import { Word64 } from "./mod.ts";

// deno-fmt-ignore
export class Sha512 extends Word64 {
  constructor(message: Uint8Array) {
    super(
      BigUint64Array.from([
        0x6A09_E667_F3BC_C908n, 0xBB67_AE85_84CA_A73Bn, 0x3C6E_F372_FE94_F82Bn, 0xA54F_F53A_5F1D_36F1n,
        0x510E_527F_ADE6_82D1n, 0x9B05_688C_2B3E_6C1Fn, 0x1F83_D9AB_FB41_BD6Bn, 0x5BE0_CD19_137E_2179n,
      ]),
      message,
    );
  }
}
