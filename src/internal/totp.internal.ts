import { generateOtp } from "./harness.internal";

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
function generateTotp(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	// get the seconds instead of milliseconds by / 1_000 and then remove the fraction by ORing with 0
	time: number = (Date.now() / 1_000) | 0,
	digits: number = 6,
	t0: number = 0,
	interval: number = 30,
	hmacAlgorithm: string = "sha256",
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	const timeInput = time % 1 !== 0 ? time | 0 : time;
	const timeFactor = ((timeInput - t0) / interval) | 0;
	const timeHex = Math.floor(timeFactor)
		.toString(16)
		.padStart(16, "0")
		.toUpperCase();
	const timeBuffer = Buffer.from(timeHex, "hex");

	return generateOtp(
		secret,
		timeBuffer,
		digits,
		hmacAlgorithm,
		truncationOffset,
		addChecksum,
	);
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
function generateTotpSha1(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	time: number = (Date.now() / 1_000) | 0,
	digits: number = 6,
	t0: number = 0,
	interval: number = 30,
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	return generateTotp(
		secret,
		time,
		digits,
		t0,
		interval,
		"sha1",
		truncationOffset,
		addChecksum,
	);
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
function generateTotpSha256(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	time: number = (Date.now() / 1_000) | 0,
	digits: number = 6,
	t0: number = 0,
	interval: number = 30,
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	return generateTotp(
		secret,
		time,
		digits,
		t0,
		interval,
		"sha256",
		truncationOffset,
		addChecksum,
	);
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
function generateTotpSha512(
	secret: string | NodeJS.ArrayBufferView | Buffer,
	time: number = (Date.now() / 1_000) | 0,
	digits: number = 6,
	t0: number = 0,
	interval: number = 30,
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	return generateTotp(
		secret,
		time,
		digits,
		t0,
		interval,
		"sha512",
		truncationOffset,
		addChecksum,
	);
}

export {
	generateTotp,
	generateTotpSha1,
	generateTotpSha256,
	generateTotpSha512,
};
