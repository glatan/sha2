import { Word32 } from "./mod.ts";

// deno-fmt-ignore
export class Sha256 extends Word32 {
  constructor(message: Uint8Array) {
    super(
      Uint32Array.from([
        0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
        0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
      ]),
      message,
    );
  }
}
