# SHA-2

SHA-2 family for Deno.

## Example

```ts
import { assertEquals } from "https://deno.land/std@0.63.0/testing/asserts.ts";
import { Sha224 } from "https://deno.land/x/sha2/@0.2.0/mod/sha224.ts";
import { Sha256 } from "https://deno.land/x/sha2/@0.2.0/mod/sha256.ts";
import { Sha384 } from "https://deno.land/x/sha2/@0.2.0/mod/sha384.ts";
import { Sha512 } from "https://deno.land/x/sha2/@0.2.0/mod/sha512.ts";
import { Sha512Trunc224 } from "https://deno.land/x/sha2/@0.2.0/mod/sha512trunc224.ts";
import { Sha512Trunc256 } from "https://deno.land/x/sha2/@0.2.0/mod/sha512trunc256.ts";

assertEquals(
  new Sha224().hashToLowerHex(new Uint8Array()),
  "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
);
assertEquals(
  new Sha256().hashToLowerHex(new Uint8Array()),
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
);
assertEquals(
  new Sha384().hashToLowerHex(new Uint8Array()),
  "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
);
assertEquals(
  new Sha512().hashToUpperHex(new Uint8Array()),
  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    .toUpperCase(),
);
assertEquals(
  new Sha512Trunc224().hashToUpperHex(new Uint8Array()),
  "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4".toUpperCase(),
);
assertEquals(
  new Sha512Trunc256().hashToUpperHex(new Uint8Array()),
  "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
    .toUpperCase(),
);
```
