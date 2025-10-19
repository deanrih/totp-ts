import type { CryptoHasher, SupportedCryptoAlgorithms } from "bun";
import type { Hmac } from "node:crypto";
import { createHmac } from "node:crypto";

const otpDigitLength = [6, 8, 10] as const;

type OtpSecret = string | Buffer;
type OtpType = "hotp" | "totp";
type OtpHashAlgorithm = "sha1" | "sha256" | "sha512";
type OtpSecretStringEncoding = "base32" | BufferEncoding;
type OtpDigitLength = (typeof otpDigitLength)[number];

interface OtpGenerationOptions {
	algorithm?: OtpHashAlgorithm;
	digits?: OtpDigitLength;
	addChecksum?: boolean;
	truncationOffset?: number;
}

// References
// https://datatracker.ietf.org/doc/html/rfc6238
// https://datatracker.ietf.org/doc/html/rfc4226

// biome-ignore format: style
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

function generateOtp(secret: Buffer, movingFactor: Buffer, options?: OtpGenerationOptions): string {
	const addChecksum = options?.addChecksum ?? false;
	const algorithm = options?.algorithm ?? "sha1";
	const digits = (options?.digits ?? 6) + Number(addChecksum);
	const truncationOffset = options?.truncationOffset ?? -1;

	const hash = getHash(algorithm, secret, movingFactor);

	// 0xF = 15 or
	// 0xF = 0000_1111
	// isolate/mask only the first 4 bits
	let offset = hash[hash.length - 1] & 0xf;

	if (0 <= truncationOffset && truncationOffset < hash.length - 4) {
		offset = truncationOffset;
	}

	// masking with 0x7FFFFFFF
	// 0111_1111_1111_1111_1111_1111_1111_1111
	// and shifting the value to the left
	// const binary = (
	// 	// 0x7F = 0111_1111
	// 	// 0xFF = 1111_1111
	// 	((hmac[offset + 0] & 0x7F) << 24) |
	// 	((hmac[offset + 1] & 0xFF) << 16) |
	// 	((hmac[offset + 2] & 0xFF) << 8) |
	// 	((hmac[offset + 3] & 0xFF) << 0)
	// );
	const binary = hash.readUInt32BE(offset) & 0x7fffffff;

	let code = binary % DIGITS_POWER[digits];

	if (addChecksum) {
		code = code * 10 + calculateChecksum(code, digits);
	}

	return code.toString().padStart(digits, "0");
}

export type { OtpDigitLength, OtpHashAlgorithm, OtpSecret, OtpSecretStringEncoding, OtpType };
export { generateOtp, otpDigitLength };
