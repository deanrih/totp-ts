# @deanrih/totp-ts

A Time-Based (RFC 6238) and HMAC-Based (RFC 4226) One-Time Password Algorithm Implementation in TypeScript.

## Installation

> NOTE: The package/library hasn't been actually published yet, these commands are placeholder

```sh
# Bun
bun add @deanrih/totp-ts
# pnpm
pnpm add @deanrih/totp-ts
# npm
npm install @deanrih/totp-ts
```

## Usage

> NOTE: The package/library hasn't been actually published yet, this example is a placeholder

```ts
import { generateTOTP } from "@deanrih/totp-ts";

const code = generateTOTP("secret-key");

console.log(`Your One-Time Password: [${code}]`);
```

Checkout the [example](https://github.com/deanrih/totp-ts/blob/main/example) folder.

## Credits/Reference

IETF RFC Datatracker

- [RFC 6238 <Time-Based One-Time Password Algorithm>](https://datatracker.ietf.org/doc/html/rfc6238)
- [RFC 4226 <HMAC-Based One-Time Password Algorithm>](https://datatracker.ietf.org/doc/html/rfc4226)
