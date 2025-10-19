import { createHmac, type Hmac } from "node:crypto";
import { base32Decode } from "@deanrih/ts-lib-codec-string";
import type { CryptoHasher, SupportedCryptoAlgorithms } from "bun";
import { barplot, bench, boxplot, do_not_optimize, run, summary, type k_state } from "mitata";

import type { OtpDigitLength, OtpHashAlgorithm } from "~/internal/harness.internal";
import { numberToBytes } from "~/internal/harness.internal";

const rounds = [
	Buffer.from("1234567890", "utf8"),
	Buffer.from("12345678901234567890", "utf8"),
	Buffer.from("12345678901234567890123456789012", "utf8"),
	Buffer.from("1234567890123456789012345678901234567890123456789012345678901234", "utf8"),
	base32Decode("JBSWY3DPEHPK3PXP"),
];

const iterations = 1_000;

function benchLoop(handler: (value: Buffer) => void): void {
	for (let idx = 0; idx < rounds.length; idx += 1) {
		const round = rounds[idx];
		do_not_optimize(handler(round));
	}
}

interface OtpGenerationOptions {
	algorithm?: OtpHashAlgorithm;
	digits?: OtpDigitLength;
	addChecksum?: boolean;
	truncationOffset?: number;
}

const nybbleMask = 0xf; // 15 or 0000_1111, mask first 4 bits or nibble/nybble

const DIGITS_POWER = [
	1,
	10,
	100, // 0 - 2
	1_000,
	10_000,
	100_000, // 3 - 5
	1_000_000,
	10_000_000,
	100_000_000, // 6 - 8
	1_000_000_000,
	10_000_000_000,
	100_000_000_000, // 9 - 11
	1_000_000_000_000,
	10_000_000_000_000,
	100_000_000_000_000, // 12 - 14
];
const DOUBLE_DIGITS = [0, 2, 4, 6, 8, 1, 3, 5, 7, 9];

function calculateChecksum(num: number, digits: number): number {
	let doubleDigit = true;
	let total = 0;

	while (0 < digits--) {
		let digit = Math.floor(num % 10);
		num /= 10;

		if (doubleDigit) {
			digit = DOUBLE_DIGITS[digit];
		}

		total += digit;
		doubleDigit = !doubleDigit;
	}

	let result = total % 10;

	if (result > 0) {
		result = 10 - result;
	}

	return result;
}

function isBun(): boolean {
	return typeof Bun !== "undefined" || (process !== undefined ? process.versions["bun"] !== undefined : false);
}

function internalHashBun(algorithm: SupportedCryptoAlgorithms, key: Uint8Array, input: Uint8Array): CryptoHasher {
	if (!isBun()) {
		throw new Error("Bun environment is not detected. This function relies on Bun's functionality to work.");
	}

	return new Bun.CryptoHasher(algorithm, key).update(input);
}

function internalHashNode(algorithm: string, key: Uint8Array, input: Uint8Array): Hmac {
	return createHmac(algorithm, key).update(input);
}

function getHash(algorithm: OtpHashAlgorithm, key: Buffer, input: Buffer): Buffer {
	const keyByteArray = new Uint8Array(key);
	const inpByteArray = new Uint8Array(input);
	const hasher = isBun() ? internalHashBun : internalHashNode;
	const result = hasher(algorithm, keyByteArray, inpByteArray).digest();
	return result;
}

function testGenerateOtpBitShift(secret: Buffer, movingFactor: Buffer, options?: OtpGenerationOptions): string {
	const addChecksum = options?.addChecksum ?? false;
	const algorithm = options?.algorithm ?? "sha1";
	const digits = (options?.digits ?? 6) + Number(addChecksum);
	const truncationOffset = options?.truncationOffset ?? -1;

	const hash = getHash(algorithm, secret, movingFactor);

	let offset = hash[hash.length - 1] & nybbleMask;

	if (0 <= truncationOffset && truncationOffset < hash.length - 4) {
		offset = truncationOffset;
	}

	// masking with 0x7FFFFFFF
	// 0111_1111_1111_1111_1111_1111_1111_1111
	// and shifting the value to the left
	const binary =
		// 0x7F = 0111_1111
		// 0xFF = 1111_1111
		((hash[offset + 0] & 0x7f) << 24) |
		((hash[offset + 1] & 0xff) << 16) |
		((hash[offset + 2] & 0xff) << 8) |
		((hash[offset + 3] & 0xff) << 0);
	// const binary = hash.readUInt32BE(offset) & 0x7fffffff;

	let code = binary % DIGITS_POWER[digits];

	if (addChecksum) {
		code = code * 10 + calculateChecksum(code, digits);
	}

	return code.toString().padStart(digits, "0");
}

function testGenerateOtpReadUInt(secret: Buffer, movingFactor: Buffer, options?: OtpGenerationOptions): string {
	const addChecksum = options?.addChecksum ?? false;
	const algorithm = options?.algorithm ?? "sha1";
	const digits = (options?.digits ?? 6) + Number(addChecksum);
	const truncationOffset = options?.truncationOffset ?? -1;

	const hash = getHash(algorithm, secret, movingFactor);

	let offset = hash[hash.length - 1] & nybbleMask;

	if (0 <= truncationOffset && truncationOffset < hash.length - 4) {
		offset = truncationOffset;
	}

	const binary = hash.readUInt32BE(offset) & 0x7fffffff;

	let code = binary % DIGITS_POWER[digits];

	if (addChecksum) {
		code = code * 10 + calculateChecksum(code, digits);
	}

	return code.toString().padStart(digits, "0");
}

const interval = 30;
const t0 = 0;
const time = 123456;
const timeInput = time % 1 !== 0 ? time | 0 : time;
const timeFactor = ((timeInput - t0) / interval) | 0;
const timeFloored = Math.floor(timeFactor);
const timeBuffer = numberToBytes(timeFloored);

// boxplot(() => {
barplot(() => {
	summary(() => {
		bench("calculate byte from hash - bitshift", () => {
			for (let iter = 0; iter < iterations; iter += 1) {
				const _ = benchLoop((x) => {
					testGenerateOtpBitShift(x, timeBuffer, { addChecksum: false, algorithm: "sha1", digits: 6, truncationOffset: -1 });
				});
			}
		}).gc("inner");

		bench("calculate byte from hash - readuint", () => {
			for (let iter = 0; iter < iterations; iter += 1) {
				const _ = benchLoop((x) => {
					testGenerateOtpReadUInt(x, timeBuffer, { addChecksum: false, algorithm: "sha1", digits: 6, truncationOffset: -1 });
				});
			}
		}).gc("inner");
	});
});

await run();
