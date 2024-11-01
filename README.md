# @deanrih/totp-ts

A Time-Based (RFC 6238) and HMAC-Based (RFC 4226) One-Time Password Algorithm Implementation in TypeScript.

## Installation

```sh
# Bun
bun add @deanrih/totp-ts
# pnpm
pnpm add @deanrih/totp-ts
# npm
npm install @deanrih/totp-ts
```

## Usage

```ts
import { generateTotp } from "@deanrih/totp-ts";

const secret = "super_S3cr37-k3y";
const password = generateTotp(secret);

console.log(`Your One-time Password: [${password}]`);
```

```ts
import { generateTotp } from "@deanrih/totp-ts";

const secret = "super_S3cr37-k3y";

console.log(`Your One-time Password: [${generateTotp(secret)}]`);
await Bun.sleep(30 * 1000); // Wait for 30 seconds to see the new code generated
console.log(`Your One-time Password: [${generateTotp(secret)}]`);
```

Checkout the [example](https://github.com/deanrih/totp-ts/blob/main/example) folder.

## Credits/Reference

IETF RFC Datatracker

- [RFC 6238 <Time-Based One-Time Password Algorithm>](https://datatracker.ietf.org/doc/html/rfc6238)
- [RFC 4226 <HMAC-Based One-Time Password Algorithm>](https://datatracker.ietf.org/doc/html/rfc4226)
