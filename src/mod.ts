import { concat } from "https://deno.land/std/bytes/mod.ts";
import * as utils from "./utils.ts";

interface Hash {
  hashToBytes(): Uint8Array;
  hashToLowerHex(): string;
  hashToUpperHex(): string;
}

// SHA-224 and SHA-256 Constant
// deno-fmt-ignore
const K32 = Uint32Array.from([
  0x428A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5, 0x3956_C25B, 0x59F1_11F1, 0x923F_82A4, 0xAB1_C5ED5,
  0xD807_AA98, 0x1283_5B01, 0x2431_85BE, 0x550C_7DC3, 0x72BE_5D74, 0x80DE_B1FE, 0x9BDC_06A7, 0xC19_BF174,
  0xE49B_69C1, 0xEFBE_4786, 0x0FC1_9DC6, 0x240C_A1CC, 0x2DE9_2C6F, 0x4A74_84AA, 0x5CB0_A9DC, 0x76F_988DA,
  0x983E_5152, 0xA831_C66D, 0xB003_27C8, 0xBF59_7FC7, 0xC6E0_0BF3, 0xD5A7_9147, 0x06CA_6351, 0x142_92967,
  0x27B7_0A85, 0x2E1B_2138, 0x4D2C_6DFC, 0x5338_0D13, 0x650A_7354, 0x766A_0ABB, 0x81C2_C92E, 0x927_22C85,
  0xA2BF_E8A1, 0xA81A_664B, 0xC24B_8B70, 0xC76C_51A3, 0xD192_E819, 0xD699_0624, 0xF40E_3585, 0x106_AA070,
  0x19A4_C116, 0x1E37_6C08, 0x2748_774C, 0x34B0_BCB5, 0x391C_0CB3, 0x4ED8_AA4A, 0x5B9C_CA4F, 0x682_E6FF3,
  0x748F_82EE, 0x78A5_636F, 0x84C8_7814, 0x8CC7_0208, 0x90BE_FFFA, 0xA450_6CEB, 0xBEF9_A3F7, 0xC67_178F2,
]);
// SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Constant
// deno-fmt-ignore
const K64 = BigUint64Array.from([
  0x428A_2F98_D728_AE22n, 0x7137_4491_23EF_65CDn, 0xB5C0_FBCF_EC4D_3B2Fn, 0xE9B5_DBA5_8189_DBBCn,
  0x3956_C25B_F348_B538n, 0x59F1_11F1_B605_D019n, 0x923F_82A4_AF19_4F9Bn, 0xAB1C_5ED5_DA6D_8118n,
  0xD807_AA98_A303_0242n, 0x1283_5B01_4570_6FBEn, 0x2431_85BE_4EE4_B28Cn, 0x550C_7DC3_D5FF_B4E2n,
  0x72BE_5D74_F27B_896Fn, 0x80DE_B1FE_3B16_96B1n, 0x9BDC_06A7_25C7_1235n, 0xC19B_F174_CF69_2694n,
  0xE49B_69C1_9EF1_4AD2n, 0xEFBE_4786_384F_25E3n, 0x0FC1_9DC6_8B8C_D5B5n, 0x240C_A1CC_77AC_9C65n,
  0x2DE9_2C6F_592B_0275n, 0x4A74_84AA_6EA6_E483n, 0x5CB0_A9DC_BD41_FBD4n, 0x76F9_88DA_8311_53B5n,
  0x983E_5152_EE66_DFABn, 0xA831_C66D_2DB4_3210n, 0xB003_27C8_98FB_213Fn, 0xBF59_7FC7_BEEF_0EE4n,
  0xC6E0_0BF3_3DA8_8FC2n, 0xD5A7_9147_930A_A725n, 0x06CA_6351_E003_826Fn, 0x1429_2967_0A0E_6E70n,
  0x27B7_0A85_46D2_2FFCn, 0x2E1B_2138_5C26_C926n, 0x4D2C_6DFC_5AC4_2AEDn, 0x5338_0D13_9D95_B3DFn,
  0x650A_7354_8BAF_63DEn, 0x766A_0ABB_3C77_B2A8n, 0x81C2_C92E_47ED_AEE6n, 0x9272_2C85_1482_353Bn,
  0xA2BF_E8A1_4CF1_0364n, 0xA81A_664B_BC42_3001n, 0xC24B_8B70_D0F8_9791n, 0xC76C_51A3_0654_BE30n,
  0xD192_E819_D6EF_5218n, 0xD699_0624_5565_A910n, 0xF40E_3585_5771_202An, 0x106A_A070_32BB_D1B8n,
  0x19A4_C116_B8D2_D0C8n, 0x1E37_6C08_5141_AB53n, 0x2748_774C_DF8E_EB99n, 0x34B0_BCB5_E19B_48A8n,
  0x391C_0CB3_C5C9_5A63n, 0x4ED8_AA4A_E341_8ACBn, 0x5B9C_CA4F_7763_E373n, 0x682E_6FF3_D6B2_B8A3n,
  0x748F_82EE_5DEF_B2FCn, 0x78A5_636F_4317_2F60n, 0x84C8_7814_A1F0_AB72n, 0x8CC7_0208_1A64_39ECn,
  0x90BE_FFFA_2363_1E28n, 0xA450_6CEB_DE82_BDE9n, 0xBEF9_A3F7_B2C6_7915n, 0xC671_78F2_E372_532Bn,
  0xCA27_3ECE_EA26_619Cn, 0xD186_B8C7_21C0_C207n, 0xEADA_7DD6_CDE0_EB1En, 0xF57D_4F7F_EE6E_D178n,
  0x06F0_67AA_7217_6FBAn, 0x0A63_7DC5_A2C8_98A6n, 0x113F_9804_BEF9_0DAEn, 0x1B71_0B35_131C_471Bn,
  0x28DB_77F5_2304_7D84n, 0x32CA_AB7B_40C7_2493n, 0x3C9E_BE0A_15C9_BEBCn, 0x431D_67C4_9C10_0D4Cn,
  0x4CC5_D4BE_CB3E_42B6n, 0x597F_299C_FC65_7E2An, 0x5FCB_6FAB_3AD6_FAECn, 0x6C44_198C_4A47_5817n,
]);

// SHA-224 and SHA-256 Functions
function ch32(x: number, y: number, z: number): number {
  return (x & y) ^ (~x & z);
}
function maj32(x: number, y: number, z: number): number {
  return (x & y) ^ (x & z) ^ (y & z);
}
function bigSigma32_0(x: number): number {
  return utils.Uint32RotateRight(x, 2) ^ utils.Uint32RotateRight(x, 13) ^
    utils.Uint32RotateRight(x, 22);
}
function bigSigma32_1(x: number): number {
  return utils.Uint32RotateRight(x, 6) ^ utils.Uint32RotateRight(x, 11) ^
    utils.Uint32RotateRight(x, 25);
}
function smallSigma32_0(x: number): number {
  return utils.Uint32RotateRight(x, 7) ^ utils.Uint32RotateRight(x, 18) ^
    (x >>> 3);
}
function smallSigma32_1(x: number): number {
  return utils.Uint32RotateRight(x, 17) ^ utils.Uint32RotateRight(x, 19) ^
    (x >>> 10);
}

// SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions
function ch64(x: bigint, y: bigint, z: bigint): bigint {
  return (x & y) ^ (~x & z);
}
function maj64(x: bigint, y: bigint, z: bigint): bigint {
  return (x & y) ^ (x & z) ^ (y & z);
}
function bigSigma64_0(x: bigint): bigint {
  return utils.BigUint64rotateRight(x, 28n) ^
    utils.BigUint64rotateRight(x, 34n) ^
    utils.BigUint64rotateRight(x, 39n);
}
function bigSigma64_1(x: bigint): bigint {
  return utils.BigUint64rotateRight(x, 14n) ^
    utils.BigUint64rotateRight(x, 18n) ^
    utils.BigUint64rotateRight(x, 41n);
}
function smallSigma64_0(x: bigint): bigint {
  return utils.BigUint64rotateRight(x, 1n) ^ utils.BigUint64rotateRight(x, 8n) ^
    (x >> 7n & 0xFFFF_FFFF_FFFF_FFFFn);
}
function smallSigma64_1(x: bigint): bigint {
  return utils.BigUint64rotateRight(x, 19n) ^
    utils.BigUint64rotateRight(x, 61n) ^ (x >> 6n) & 0xFFFF_FFFF_FFFF_FFFFn;
}

// for 32bit word SHA-2 family(SHA-224 and SHA-256)
export class Word32 implements Hash {
  #finished: boolean;
  #message: Uint8Array;
  #status: Uint32Array;
  #wordBlock: Uint32Array;
  protected constructor(h: Uint32Array, message: Uint8Array) {
    this.#finished = false;
    this.#message = message;
    this.#status = h;
    this.#wordBlock = new Uint32Array(16);
  }
  protected padding() {
    let paddedMessage = Uint8Array.from(this.#message);
    const messageByteLength = this.#message.length;
    const messageBitLength: bigint = BigInt(messageByteLength) * 8n;
    // append 0x80
    paddedMessage = concat(paddedMessage, Uint8Array.from([0x80]));
    // append zeros
    paddedMessage = concat(
      paddedMessage,
      new Uint8Array(((64 - (messageByteLength + 8 + 1)) % 64) & 0b0011_1111),
    );
    // append bit-length of message
    paddedMessage = concat(
      paddedMessage,
      Uint8Array.from([
        Number((messageBitLength >> 56n) & 0xFFn),
        Number((messageBitLength >> 48n) & 0xFFn),
        Number((messageBitLength >> 40n) & 0xFFn),
        Number((messageBitLength >> 32n) & 0xFFn),
        Number((messageBitLength >> 24n) & 0xFFn),
        Number((messageBitLength >> 16n) & 0xFFn),
        Number((messageBitLength >> 8n) & 0xFFn),
        Number(messageBitLength & 0xFFn),
      ]),
    );
    this.#wordBlock = utils.toUint32Array(paddedMessage);
  }
  protected round() {
    let a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0;
    let temp_1 = 0, temp_2 = 0;
    let w = new Uint32Array(64);
    for (let i = 0; i < this.#wordBlock.length / 16; i++) {
      for (let t = 0; t < 16; t++) {
        w[t] = this.#wordBlock[t + i * 16];
      }
      for (let t = 16; t < 64; t++) {
        w[t] = smallSigma32_1(w[t - 2]) +
          w[t - 7] +
          smallSigma32_0(w[t - 15]) +
          w[t - 16];
      }
      a = this.#status[0];
      b = this.#status[1];
      c = this.#status[2];
      d = this.#status[3];
      e = this.#status[4];
      f = this.#status[5];
      g = this.#status[6];
      h = this.#status[7];
      for (let t = 0; t < 64; t++) {
        temp_1 = h +
          bigSigma32_1(e) +
          ch32(e, f, g) +
          K32[t] +
          w[t];
        temp_2 = bigSigma32_0(a) +
          maj32(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp_1;
        d = c;
        c = b;
        b = a;
        a = temp_1 + temp_2;
      }
      this.#status[0] = this.#status[0] + a;
      this.#status[1] = this.#status[1] + b;
      this.#status[2] = this.#status[2] + c;
      this.#status[3] = this.#status[3] + d;
      this.#status[4] = this.#status[4] + e;
      this.#status[5] = this.#status[5] + f;
      this.#status[6] = this.#status[6] + g;
      this.#status[7] = this.#status[7] + h;
    }
  }
  hashToBytes(): Uint8Array {
    if (this.#finished) {
      return new Uint8Array();
    }
    this.padding();
    this.round();
    this.#finished = true;
    return Uint8Array.from(utils.Uint32ArrayToUint8Array(this.#status));
  }
  hashToLowerHex(): string {
    return utils.bytesToLowerHex(this.hashToBytes());
  }
  hashToUpperHex(): string {
    return this.hashToLowerHex().toUpperCase();
  }
}

// for 64bit word SHA-2 family(SHA-384, SHA-512, SHA-512/224 and SHA-512/256)
export class Word64 implements Hash {
  #finished: boolean;
  #message: Uint8Array;
  #status: BigUint64Array;
  #wordBlock: BigUint64Array;
  protected constructor(h: BigUint64Array, message: Uint8Array) {
    this.#finished = false;
    this.#message = message;
    this.#status = h;
    this.#wordBlock = new BigUint64Array(16);
  }
  protected padding() {
    let paddedMessage = Uint8Array.from(this.#message);
    const messageByteLength = this.#message.length;
    const messageBitLength: bigint = BigInt(messageByteLength) * 8n;
    // append 0x80
    paddedMessage = concat(paddedMessage, Uint8Array.from([0x80]));
    // append zeros
    paddedMessage = concat(
      paddedMessage,
      new Uint8Array(
        ((128 - (messageByteLength + 16 + 1)) % 128) & 0b0111_1111,
      ),
    );
    // append bit-length of message
    paddedMessage = concat(
      paddedMessage,
      Uint8Array.from([
        Number((messageBitLength >> 120n) & 0xFFn),
        Number((messageBitLength >> 112n) & 0xFFn),
        Number((messageBitLength >> 104n) & 0xFFn),
        Number((messageBitLength >> 96n) & 0xFFn),
        Number((messageBitLength >> 88n) & 0xFFn),
        Number((messageBitLength >> 80n) & 0xFFn),
        Number((messageBitLength >> 72n) & 0xFFn),
        Number((messageBitLength >> 64n) & 0xFFn),
        Number((messageBitLength >> 56n) & 0xFFn),
        Number((messageBitLength >> 48n) & 0xFFn),
        Number((messageBitLength >> 40n) & 0xFFn),
        Number((messageBitLength >> 32n) & 0xFFn),
        Number((messageBitLength >> 24n) & 0xFFn),
        Number((messageBitLength >> 16n) & 0xFFn),
        Number((messageBitLength >> 8n) & 0xFFn),
        Number(messageBitLength & 0xFFn),
      ]),
    );
    this.#wordBlock = utils.toBigUint64Array(paddedMessage);
  }
  protected round() {
    let a = 0n, b = 0n, c = 0n, d = 0n, e = 0n, f = 0n, g = 0n, h = 0n;
    let temp_1 = 0n, temp_2 = 0n;
    let w = new BigUint64Array(80);
    for (let i = 0; i < this.#wordBlock.length / 16; i++) {
      for (let t = 0; t < 16; t++) {
        w[t] = this.#wordBlock[t + i * 16];
      }
      for (let t = 16; t < 80; t++) {
        w[t] = (smallSigma64_1(w[t - 2]) +
          w[t - 7] +
          smallSigma64_0(w[t - 15]) +
          w[t - 16]);
      }
      a = this.#status[0];
      b = this.#status[1];
      c = this.#status[2];
      d = this.#status[3];
      e = this.#status[4];
      f = this.#status[5];
      g = this.#status[6];
      h = this.#status[7];
      for (let t = 0; t < 80; t++) {
        temp_1 = (h +
          bigSigma64_1(e) +
          ch64(e, f, g) +
          K64[t] +
          w[t]) & 0xFFFF_FFFF_FFFF_FFFFn;
        temp_2 = (bigSigma64_0(a) +
          maj64(a, b, c)) & 0xFFFF_FFFF_FFFF_FFFFn;
        h = g;
        g = f;
        f = e;
        e = (d + temp_1) & 0xFFFF_FFFF_FFFF_FFFFn;
        d = c;
        c = b;
        b = a;
        a = (temp_1 + temp_2) & 0xFFFF_FFFF_FFFF_FFFFn;
      }
      this.#status[0] = this.#status[0] + a;
      this.#status[1] = this.#status[1] + b;
      this.#status[2] = this.#status[2] + c;
      this.#status[3] = this.#status[3] + d;
      this.#status[4] = this.#status[4] + e;
      this.#status[5] = this.#status[5] + f;
      this.#status[6] = this.#status[6] + g;
      this.#status[7] = this.#status[7] + h;
    }
  }
  hashToBytes(): Uint8Array {
    if (this.#finished) {
      return new Uint8Array();
    }
    this.padding();
    this.round();
    this.#finished = true;
    return Uint8Array.from(utils.BigUint64ArrayToUint8Array(this.#status));
  }
  hashToLowerHex(): string {
    return utils.bytesToLowerHex(this.hashToBytes());
  }
  hashToUpperHex(): string {
    return this.hashToLowerHex().toUpperCase();
  }
}
