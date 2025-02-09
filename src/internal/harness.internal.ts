import type { CryptoHasher, SupportedCryptoAlgorithms } from "bun";
import type { BinaryLike, Encoding, Hmac, KeyObject } from "node:crypto";
import { createHmac } from "node:crypto";

const unreasonableDigitError = Error("Unreasonable Digit Length");

// References
// https://datatracker.ietf.org/doc/html/rfc6238
// https://datatracker.ietf.org/doc/html/rfc4226

// biome-ignore format:
const DIGITS_POWER = [
	1, 10, 100, // 0 - 2
	1_000, 10_000, 100_000, // 3 - 5
	1_000_000, 10_000_000, 100_000_000, // 6 - 8
	1_000_000_000, 10_000_000_000, 100_000_000_000, // 9 - 11
	1_000_000_000_000, 10_000_000_000_000, 100_000_000_000_000, // 12 - 14
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
	return (
		typeof Bun !== "undefined" ||
		(process !== undefined ? process.versions["bun"] !== undefined : false)
	);
}

function internalHashBun(
	algorithm: SupportedCryptoAlgorithms,
	key: string | NodeJS.TypedArray,
	input: Bun.BlobOrStringOrBuffer,
	inputEncoding?: Encoding,
): CryptoHasher {
	if (!isBun()) {
		throw new Error(
			"Bun environment is not detected. This function relies on Bun's functionality to work.",
		);
	}

	return new Bun.CryptoHasher(algorithm, key).update(input, inputEncoding);
}

function internalHashNode(
	algorithm: string,
	key: BinaryLike | KeyObject,
	input: BinaryLike | string,
	inputEncoding?: Encoding,
): Hmac {
	if (inputEncoding !== undefined && typeof input === "string") {
		return createHmac(algorithm, key).update(input, inputEncoding);
	}

	return createHmac(algorithm, key).update(input);
}

function getHash(
	algorithm: SupportedCryptoAlgorithms | string,
	key: string | BinaryLike | KeyObject,
	input: Bun.BlobOrStringOrBuffer | BinaryLike | string,
	inputEncoding?: Encoding,
): Buffer {
	if (isBun()) {
		return internalHashBun(
			<SupportedCryptoAlgorithms>algorithm,
			<string>key,
			<Bun.BlobOrStringOrBuffer>input,
			inputEncoding,
		).digest();
	}

	algorithm = <string>algorithm;
	key = <BinaryLike | KeyObject>key;

	if (inputEncoding !== undefined && typeof input === "string") {
		return internalHashNode(algorithm, key, input, inputEncoding).digest();
	}

	input = <BinaryLike>input;
	return internalHashNode(algorithm, key, input).digest();
}

function generateOtp(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	movingFactor: Buffer,
	digits: number = 6,
	hmacAlgorithm: string = "sha256",
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	if (digits > 12) {
		throw unreasonableDigitError;
	}

	const finalSecret =
		typeof secret !== "string" ? secret : Buffer.from(secret, "utf8");
	const resultDigits = addChecksum ? digits + 1 : digits;
	const hmac = getHash(
		hmacAlgorithm,
		<NodeJS.ArrayBufferView>finalSecret,
		<NodeJS.ArrayBufferView>(movingFactor as unknown),
	);
	// const hmac = createHmac(hmacAlgorithm, <NodeJS.ArrayBufferView>finalSecret)
	// .update(<NodeJS.ArrayBufferView>(movingFactor as unknown))
	// .digest();
	// const hmac = createHmac(hmacAlgorithm, finalSecret)
	// 	.update(movingFactor)
	// 	.digest();

	// 0xF = 15 or
	// 0xF = 0000_1111
	// isolate/mask only the first 4 bits
	let offset = hmac[hmac.length - 1] & 0xf;

	if (0 <= truncationOffset && truncationOffset < hmac.length - 4) {
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
	const binary = hmac.readUInt32BE(offset) & 0x7fffffff;

	let code = binary % DIGITS_POWER[digits];

	if (addChecksum) {
		code = code * 10 + calculateChecksum(code, digits);
	}

	return code.toString().padStart(resultDigits, "0");
}

export { generateOtp };
