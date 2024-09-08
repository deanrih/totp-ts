import { createHmac } from "crypto";

// References
// https://datatracker.ietf.org/doc/html/rfc6238
// https://datatracker.ietf.org/doc/html/rfc4226

const DIGITS_POWER = [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000, 10_000_000_000];
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

function generateOTP(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	movingFactor: Buffer,
	digits: number = 6,
	hmacAlgorithm: string = "sha256",
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	const finalSecret = typeof secret !== "string" ? secret : Buffer.from(secret, "utf8");
	const resultDigits = addChecksum ? (digits + 1) : digits;
	const hmac = createHmac(hmacAlgorithm, finalSecret)
		.update(movingFactor)
		.digest();

	// 0xF = 15 or
	// 0xF = 0000_1111
	// isolate/mask only the first 4 bits
	let offset = hmac[hmac.length - 1] & 0xF;

	if (
		(0 <= truncationOffset) &&
		(truncationOffset < (hmac.length - 4))
	) {
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
	const binary = (hmac.readUInt32BE(offset) & 0x7FFFFFFF);

	let code = binary % DIGITS_POWER[digits];

	if (addChecksum) {
		code = (code * 10) + calculateChecksum(code, digits);
	}

	return code.toString().padStart(resultDigits, "0");
}

/**
 * Generates a HMAC-Based One-Time Password (HOTP) based on the given parameters.
 *
 * HOTP is an OTP algorithm that uses a counter value in combination with a shared secret to generate a unique code.
 * The counter is manually incremented each time an OTP is generated, providing sequential OTPs.
 * @param secret The shared secret, key, or seed used in the HMAC algorithm to generate the OTP. This should be a string or a buffer.
 * @param counter The counter value that is incremented for each OTP generated. This value should be a positive integer and should be managed by the application to ensure sequential OTPs.
 * @param digits The number of digits in the resulting OTP. The ideal range is between 6 to 8 digits.
 * ```ts
 * Default: 6
 * ```
 * @param hmacAlgorithm The HMAC algorithm to be used for generating the OTP. Common choices include 'SHA1', 'SHA256', and 'SHA512'.
 * ```ts
 * Default: "SHA256"
 * ```
 * @param truncationOffset The offset used for dynamic truncation of the HMAC result. This value is usually between 0 and 15.
 * ```ts
 * Default: -1
 * ```
 * @param addChecksum Whether to include a checksum or not. This is typically a boolean indicating whether a checksum digit should be added to the OTP.
 * ```ts
 * Default: false
 * ```
 * @returns The generated OTP as a string, which is a numeric code of the specified length.
 */
export function generateHOTP(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	counter: number,
	digits: number = 6,
	hmacAlgorithm: string = "sha256",
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	const counterBuffer = Buffer.alloc(8);
	// for (let idx = counterBuffer.length - 1; idx >= 0; idx--) {
	// 	counterBuffer[idx] = counter & 0xFF;
	// 	counter >>= 8;
	// }
	counterBuffer.writeBigInt64BE(BigInt(counter), 0);

	return generateOTP(secret, counterBuffer, digits, hmacAlgorithm, truncationOffset, addChecksum);
}

/**
 * Generates a HMAC-Based One-Time Password (HOTP) based on the given parameters.
 *
 * HOTP is an OTP algorithm that uses a counter value in combination with a shared secret to generate a unique code.
 * The counter is manually incremented each time an OTP is generated, providing sequential OTPs.
 * @param secret The shared secret, key, or seed used in the HMAC algorithm to generate the OTP. This should be a string or a buffer.
 * @param counter The counter value that is incremented for each OTP generated. This value should be a positive integer and should be managed by the application to ensure sequential OTPs.
 * @param digits The number of digits in the resulting OTP. The ideal range is between 6 to 8 digits.
 * ```ts
 * Default: 6
 * ```
 * @param truncationOffset The offset used for dynamic truncation of the HMAC result. This value is usually between 0 and 15.
 * ```ts
 * Default: -1
 * ```
 * @param addChecksum Whether to include a checksum or not. This is typically a boolean indicating whether a checksum digit should be added to the OTP.
 * ```ts
 * Default: false
 * ```
 * @returns The generated OTP as a string, which is a numeric code of the specified length.
 */
export function generateHOTPSHA1(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	counter: number,
	digits: number = 6,
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	const counterBuffer = Buffer.alloc(8);
	// for (let idx = counterBuffer.length - 1; idx >= 0; idx--) {
	// 	counterBuffer[idx] = counter & 0xFF;
	// 	counter >>= 8;
	// }
	counterBuffer.writeBigInt64BE(BigInt(counter), 0);

	return generateOTP(secret, counterBuffer, digits, "sha1", truncationOffset, addChecksum);
}

/**
 * Generates a HMAC-Based One-Time Password (HOTP) based on the given parameters.
 *
 * HOTP is an OTP algorithm that uses a counter value in combination with a shared secret to generate a unique code.
 * The counter is manually incremented each time an OTP is generated, providing sequential OTPs.
 * @param secret The shared secret, key, or seed used in the HMAC algorithm to generate the OTP. This should be a string or a buffer.
 * @param counter The counter value that is incremented for each OTP generated. This value should be a positive integer and should be managed by the application to ensure sequential OTPs.
 * @param digits The number of digits in the resulting OTP. The ideal range is between 6 to 8 digits.
 * ```ts
 * Default: 6
 * ```
 * @param truncationOffset The offset used for dynamic truncation of the HMAC result. This value is usually between 0 and 15.
 * ```ts
 * Default: -1
 * ```
 * @param addChecksum Whether to include a checksum or not. This is typically a boolean indicating whether a checksum digit should be added to the OTP.
 * ```ts
 * Default: false
 * ```
 * @returns The generated OTP as a string, which is a numeric code of the specified length.
 */
export function generateHOTPSHA256(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	counter: number,
	digits: number = 6,
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	const counterBuffer = Buffer.alloc(8);
	// for (let idx = counterBuffer.length - 1; idx >= 0; idx--) {
	// 	counterBuffer[idx] = counter & 0xFF;
	// 	counter >>= 8;
	// }
	counterBuffer.writeBigInt64BE(BigInt(counter), 0);

	return generateOTP(secret, counterBuffer, digits, "sha256", truncationOffset, addChecksum);
}

/**
 * Generates a HMAC-Based One-Time Password (HOTP) based on the given parameters.
 *
 * HOTP is an OTP algorithm that uses a counter value in combination with a shared secret to generate a unique code.
 * The counter is manually incremented each time an OTP is generated, providing sequential OTPs.
 * @param secret The shared secret, key, or seed used in the HMAC algorithm to generate the OTP. This should be a string or a buffer.
 * @param counter The counter value that is incremented for each OTP generated. This value should be a positive integer and should be managed by the application to ensure sequential OTPs.
 * @param digits The number of digits in the resulting OTP. The ideal range is between 6 to 8 digits.
 * ```ts
 * Default: 6
 * ```
 * @param truncationOffset The offset used for dynamic truncation of the HMAC result. This value is usually between 0 and 15.
 * ```ts
 * Default: -1
 * ```
 * @param addChecksum Whether to include a checksum or not. This is typically a boolean indicating whether a checksum digit should be added to the OTP.
 * ```ts
 * Default: false
 * ```
 * @returns The generated OTP as a string, which is a numeric code of the specified length.
 */
export function generateHOTPSHA512(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	counter: number,
	digits: number = 6,
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	const counterBuffer = Buffer.alloc(8);
	// for (let idx = counterBuffer.length - 1; idx >= 0; idx--) {
	// 	counterBuffer[idx] = counter & 0xFF;
	// 	counter >>= 8;
	// }
	counterBuffer.writeBigInt64BE(BigInt(counter), 0);

	return generateOTP(secret, counterBuffer, digits, "sha1", truncationOffset, addChecksum);
}

/**
 * Generates a Time-Based One-Time Password (TOTP) based on the given parameters. Primarily secret and time (moving factor).
 *
 * TOTP is a time-based OTP algorithm that uses a shared secret and the current time to generate a unique code.
 * @param secret The shared secret, key, or seed used in the HMAC algorithm to generate the OTP. This should be a string or a buffer.
 * @param time The moving factor, representing the current time, used to generate the OTP. This is usually the number of intervals that have elapsed since the epoch.
 * ```ts
 * Default: (Date.now() / 1_1000) | 0
 * ```
 * @param digits The number of digits in the resulting OTP. The ideal range is between 6 to 8 digits.
 * ```ts
 * Default: 6
 * ```
 * @param t0 The initial timestamp (epoch) from which the time intervals are counted. Typically, this is set to the Unix epoch or a specific start time.
 * ```ts
 * Default: 0
 * ```
 * @param interval The time interval in seconds between OTP changes. Common values are 30 or 60 seconds.
 * ```ts
 * Default: 30
 * ```
 * @param hmacAlgorithm The HMAC algorithm to be used for generating the OTP. Common choices include 'SHA1', 'SHA256', and 'SHA512'.
 * ```ts
 * Default: "SHA256"
 * ```
 * @param truncationOffset The offset used for dynamic truncation of the HMAC result. This value is usually between 0 and 15.
 * ```ts
 * Default: -1
 * ```
 * @param addChecksum Whether to include a checksum or not. This is typically a boolean indicating whether a checksum digit should be added to the OTP.
 * ```ts
 * Default: false
 * ```
 * @returns The generated OTP as a string, which is a numeric code of the specified length.
 */
export function generateTOTP(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	time: number = (Date.now() / 1_000) | 0,
	digits: number = 6,
	t0: number = 0,
	interval: number = 30,
	hmacAlgorithm: string = "sha256",
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	const timeInput = (time % 1 !== 0) ? time | 0 : time;
	const timeFactor = ((timeInput - t0) / interval) | 0;
	const timeHex = Math.floor(timeFactor).toString(16).padStart(16, "0").toUpperCase();
	const timeBuffer = Buffer.from(timeHex, "hex");

	return generateOTP(secret, timeBuffer, digits, hmacAlgorithm, truncationOffset, addChecksum);
}

/**
 * Generates a Time-Based One-Time Password (TOTP) based on the given parameters. Primarily secret and time (moving factor).
 *
 * TOTP is a time-based OTP algorithm that uses a shared secret and the current time to generate a unique code.
 * @param secret The shared secret, key, or seed used in the HMAC algorithm to generate the OTP. This should be a string or a buffer.
 * @param time The moving factor, representing the current time, used to generate the OTP. This is usually the number of intervals that have elapsed since the epoch.
 * ```ts
 * Default: (Date.now() / 1_1000) | 0
 * ```
 * @param digits The number of digits in the resulting OTP. The ideal range is between 6 to 8 digits.
 * ```ts
 * Default: 6
 * ```
 * @param t0 The initial timestamp (epoch) from which the time intervals are counted. Typically, this is set to the Unix epoch or a specific start time.
 * ```ts
 * Default: 0
 * ```
 * @param interval The time interval in seconds between OTP changes. Common values are 30 or 60 seconds.
 * ```ts
 * Default: 30
 * ```
 * @param truncationOffset The offset used for dynamic truncation of the HMAC result. This value is usually between 0 and 15.
 * ```ts
 * Default: -1
 * ```
 * @param addChecksum Whether to include a checksum or not. This is typically a boolean indicating whether a checksum digit should be added to the OTP.
 * ```ts
 * Default: false
 * ```
 * @returns The generated OTP as a string, which is a numeric code of the specified length.
 */
export function generateTOTPSHA1(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	time: number = (Date.now() / 1_000) | 0,
	digits: number = 6,
	t0: number = 0,
	interval: number = 30,
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	return generateTOTP(secret, time, digits, t0, interval, "sha1", truncationOffset, addChecksum);
}

/**
 * Generates a Time-Based One-Time Password (TOTP) based on the given parameters. Primarily secret and time (moving factor).
 *
 * TOTP is a time-based OTP algorithm that uses a shared secret and the current time to generate a unique code.
 * @param secret The shared secret, key, or seed used in the HMAC algorithm to generate the OTP. This should be a string or a buffer.
 * @param time The moving factor, representing the current time, used to generate the OTP. This is usually the number of intervals that have elapsed since the epoch.
 * ```ts
 * Default: (Date.now() / 1_1000) | 0
 * ```
 * @param digits The number of digits in the resulting OTP. The ideal range is between 6 to 8 digits.
 * ```ts
 * Default: 6
 * ```
 * @param t0 The initial timestamp (epoch) from which the time intervals are counted. Typically, this is set to the Unix epoch or a specific start time.
 * ```ts
 * Default: 0
 * ```
 * @param interval The time interval in seconds between OTP changes. Common values are 30 or 60 seconds.
 * ```ts
 * Default: 30
 * ```
 * @param truncationOffset The offset used for dynamic truncation of the HMAC result. This value is usually between 0 and 15.
 * ```ts
 * Default: -1
 * ```
 * @param addChecksum Whether to include a checksum or not. This is typically a boolean indicating whether a checksum digit should be added to the OTP.
 * ```ts
 * Default: false
 * ```
 * @returns The generated OTP as a string, which is a numeric code of the specified length.
 */
export function generateTOTPSHA256(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	time: number = (Date.now() / 1_000) | 0,
	digits: number = 6,
	t0: number = 0,
	interval: number = 30,
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	return generateTOTP(secret, time, digits, t0, interval, "sha256", truncationOffset, addChecksum);
}

/**
 * Generates a Time-Based One-Time Password (TOTP) based on the given parameters. Primarily secret and time (moving factor).
 *
 * TOTP is a time-based OTP algorithm that uses a shared secret and the current time to generate a unique code.
 * @param secret The shared secret, key, or seed used in the HMAC algorithm to generate the OTP. This should be a string or a buffer.
 * @param time The moving factor, representing the current time, used to generate the OTP. This is usually the number of intervals that have elapsed since the epoch.
 * ```ts
 * Default: (Date.now() / 1_1000) | 0
 * ```
 * @param digits The number of digits in the resulting OTP. The ideal range is between 6 to 8 digits.
 * ```ts
 * Default: 6
 * ```
 * @param t0 The initial timestamp (epoch) from which the time intervals are counted. Typically, this is set to the Unix epoch or a specific start time.
 * ```ts
 * Default: 0
 * ```
 * @param interval The time interval in seconds between OTP changes. Common values are 30 or 60 seconds.
 * ```ts
 * Default: 30
 * ```
 * @param truncationOffset The offset used for dynamic truncation of the HMAC result. This value is usually between 0 and 15.
 * ```ts
 * Default: -1
 * ```
 * @param addChecksum Whether to include a checksum or not. This is typically a boolean indicating whether a checksum digit should be added to the OTP.
 * ```ts
 * Default: false
 * ```
 * @returns The generated OTP as a string, which is a numeric code of the specified length.
 */
export function generateTOTPSHA512(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	time: number = (Date.now() / 1_000) | 0,
	digits: number = 6,
	t0: number = 0,
	interval: number = 30,
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	return generateTOTP(secret, time, digits, t0, interval, "sha512", truncationOffset, addChecksum);
}