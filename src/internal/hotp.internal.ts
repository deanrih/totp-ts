import { base32Decode } from "@deanrih/ts-lib-codec-string";

import type { OtpHashAlgorithm, OtpSecretEncoding } from "./harness.internal";
import { generateOtp } from "./harness.internal";

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
function generateHotp(
	secret: Buffer,
	secretEncoding?: "buffer",
	counter?: number,
	digits?: number,
	hmacAlgorithm?: OtpHashAlgorithm,
	truncationOffset?: number,
	addChecksum?: boolean,
): string;
function generateHotp(
	secret: string,
	secretEncoding?: "base32",
	counter?: number,
	digits?: number,
	hmacAlgorithm?: OtpHashAlgorithm,
	truncationOffset?: number,
	addChecksum?: boolean,
): string;
function generateHotp(
	secret: string,
	secretEncoding?: OtpSecretEncoding,
	counter?: number,
	digits?: number,
	hmacAlgorithm?: OtpHashAlgorithm,
	truncationOffset?: number,
	addChecksum?: boolean,
): string;
function generateHotp(
	secret: string | Buffer,
	secretEncoding: OtpSecretEncoding = "buffer",
	counter: number = 0,
	digits: number = 6,
	hmacAlgorithm: OtpHashAlgorithm = "sha256",
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	const counterBuffer = Buffer.alloc(8);
	// for (let idx = counterBuffer.length - 1; idx >= 0; idx--) {
	// 	counterBuffer[idx] = counter & 0xFF;
	// 	counter >>= 8;
	// }
	counterBuffer.writeBigInt64BE(BigInt(counter), 0);

	const secretBuffer =
		typeof secret !== "string"
			? secret
			: secretEncoding === "base32"
				? base32Decode(secret)
				: Buffer.from(secret, <BufferEncoding>secretEncoding);

	return generateOtp(secretBuffer, counterBuffer, digits, hmacAlgorithm, truncationOffset, addChecksum);
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
function generateHotpSha1(
	secret: Buffer,
	secretEncoding?: "buffer",
	counter?: number,
	digits?: number,
	truncationOffset?: number,
	addChecksum?: boolean,
): string;
function generateHotpSha1(
	secret: string,
	secretEncoding?: "base32",
	counter?: number,
	digits?: number,
	truncationOffset?: number,
	addChecksum?: boolean,
): string;
function generateHotpSha1(
	secret: string,
	secretEncoding?: OtpSecretEncoding,
	counter?: number,
	digits?: number,
	truncationOffset?: number,
	addChecksum?: boolean,
): string;
function generateHotpSha1(
	secret: string | Buffer,
	secretEncoding: OtpSecretEncoding = "buffer",
	counter: number = 0,
	digits: number = 6,
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	if (typeof secret === "string") {
		return generateHotp(secret, secretEncoding, counter, digits, "sha1", truncationOffset, addChecksum);
	}

	return generateHotp(secret, "buffer", counter, digits, "sha1", truncationOffset, addChecksum);
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
function generateHotpSha256(
	secret: Buffer,
	secretEncoding?: "buffer",
	counter?: number,
	digits?: number,
	truncationOffset?: number,
	addChecksum?: boolean,
): string;
function generateHotpSha256(
	secret: string,
	secretEncoding?: "base32",
	counter?: number,
	digits?: number,
	truncationOffset?: number,
	addChecksum?: boolean,
): string;
function generateHotpSha256(
	secret: string,
	secretEncoding?: OtpSecretEncoding,
	counter?: number,
	digits?: number,
	truncationOffset?: number,
	addChecksum?: boolean,
): string;
function generateHotpSha256(
	secret: string | Buffer,
	secretEncoding: OtpSecretEncoding = "buffer",
	counter: number = 0,
	digits: number = 6,
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	if (typeof secret === "string") {
		return generateHotp(secret, secretEncoding, counter, digits, "sha256", truncationOffset, addChecksum);
	}

	return generateHotp(secret, "buffer", counter, digits, "sha256", truncationOffset, addChecksum);
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
function generateHotpSha512(
	secret: Buffer,
	secretEncoding?: "buffer",
	counter?: number,
	digits?: number,
	truncationOffset?: number,
	addChecksum?: boolean,
): string;
function generateHotpSha512(
	secret: string,
	secretEncoding?: "base32",
	counter?: number,
	digits?: number,
	truncationOffset?: number,
	addChecksum?: boolean,
): string;
function generateHotpSha512(
	secret: string,
	secretEncoding?: OtpSecretEncoding,
	counter?: number,
	digits?: number,
	truncationOffset?: number,
	addChecksum?: boolean,
): string;
function generateHotpSha512(
	secret: string | Buffer,
	secretEncoding: OtpSecretEncoding = "buffer",
	counter: number = 0,
	digits: number = 6,
	truncationOffset: number = -1,
	addChecksum: boolean = false,
): string {
	if (typeof secret === "string") {
		return generateHotp(secret, secretEncoding, counter, digits, "sha512", truncationOffset, addChecksum);
	}

	return generateHotp(secret, "buffer", counter, digits, "sha512", truncationOffset, addChecksum);
}

export { generateHotp, generateHotpSha1, generateHotpSha256, generateHotpSha512 };
