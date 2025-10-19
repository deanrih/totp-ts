import { base32Decode } from "@deanrih/ts-lib-codec-string";

import type { OtpSecret, OtpHashAlgorithm, OtpSecretStringEncoding, OtpDigitLength } from "./harness.internal";
import { generateOtp } from "./harness.internal";

interface HotpOptions {
	addChecksum?: boolean;
	algorithm?: OtpHashAlgorithm;
	digits?: OtpDigitLength;
	secretEncoding?: OtpSecretStringEncoding;
	truncationOffset?: number;
}
interface HotpBufferSecretOptions extends Omit<HotpOptions, "secretEncoding"> {}
interface HotpStringSecretOptions extends HotpOptions {}

interface HotpSpecificOptions extends Omit<HotpOptions, "algorithm"> {}
interface HotpSpecificBufferSecretOptions extends Omit<HotpSpecificOptions, "secretEncoding"> {}
interface HotpSpecificStringSecretOptions extends HotpSpecificOptions {}

function generateHotp(secret: Buffer, counter: number, options?: HotpBufferSecretOptions): string;
function generateHotp(secret: string, counter: number, options?: HotpStringSecretOptions): string;
function generateHotp(secret: OtpSecret, counter: number, options?: HotpOptions): string;
function generateHotp(secret: OtpSecret, counter: number, options?: HotpOptions): string {
	const secretEncoding = options?.secretEncoding ?? "base32";

	const movingFactorBuffer = Buffer.alloc(8);
	movingFactorBuffer.writeBigInt64BE(BigInt(counter), 0);

	let secretBuffer: Buffer;

	if (typeof secret === "string") {
		secretBuffer = secretEncoding === "base32" ? base32Decode(secret) : Buffer.from(secret, secretEncoding);
	} else {
		secretBuffer = secret;
	}

	return generateOtp(secretBuffer, movingFactorBuffer, { ...options });
}

function generateHotpSha1(secret: Buffer, counter: number, options?: HotpSpecificBufferSecretOptions): string;
function generateHotpSha1(secret: string, counter: number, options?: HotpSpecificStringSecretOptions): string;
function generateHotpSha1(secret: OtpSecret, counter: number, options?: HotpSpecificOptions): string {
	return generateHotp(secret, counter, { ...options, algorithm: "sha1" });
}

function generateHotpSha256(secret: Buffer, counter: number, options?: HotpSpecificBufferSecretOptions): string;
function generateHotpSha256(secret: string, counter: number, options?: HotpSpecificStringSecretOptions): string;
function generateHotpSha256(secret: OtpSecret, counter: number, options?: HotpSpecificOptions): string {
	return generateHotp(secret, counter, { ...options, algorithm: "sha256" });
}

function generateHotpSha512(secret: Buffer, counter: number, options?: HotpSpecificBufferSecretOptions): string;
function generateHotpSha512(secret: string, counter: number, options?: HotpSpecificStringSecretOptions): string;
function generateHotpSha512(secret: OtpSecret, counter: number, options?: HotpSpecificOptions): string {
	return generateHotp(secret, counter, { ...options, algorithm: "sha512" });
}

export { generateHotp, generateHotpSha1, generateHotpSha256, generateHotpSha512 };
