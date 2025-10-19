import { base32Decode } from "@deanrih/ts-lib-codec-string";

import type { OtpSecret, OtpHashAlgorithm, OtpSecretStringEncoding, OtpDigitLength } from "./harness.internal";
import { generateOtp } from "./harness.internal";

interface TotpOptions {
	addChecksum?: boolean;
	algorithm?: OtpHashAlgorithm;
	digits?: OtpDigitLength;
	interval?: number;
	secretEncoding?: OtpSecretStringEncoding;
	t0?: number;
	time?: number;
	truncationOffset?: number;
}
interface TotpBufferSecretOptions extends Omit<TotpOptions, "secretEncoding"> {}
interface TotpStringSecretOptions extends TotpOptions {}

interface TotpSpecificOptions extends Omit<TotpOptions, "algorithm"> {}
interface TotpSpecificBufferSecretOptions extends Omit<TotpSpecificOptions, "secretEncoding"> {}
interface TotpSpecificStringSecretOptions extends TotpSpecificOptions {}

function generateTotp(secret: Buffer, options?: TotpBufferSecretOptions): string;
function generateTotp(secret: string, options?: TotpStringSecretOptions): string;
function generateTotp(secret: OtpSecret, options?: TotpOptions): string;
function generateTotp(secret: OtpSecret, options?: TotpOptions): string {
	const secretEncoding = options?.secretEncoding ?? "base32";

	const interval = options?.interval ?? 30;
	const t0 = options?.t0 ?? 0;
	const time = options?.time ?? (Date.now() / 1_000) | 0;

	const timeInput = time % 1 !== 0 ? time | 0 : time;
	const timeFactor = ((timeInput - t0) / interval) | 0;
	const timeHex = Math.floor(timeFactor).toString(16).padStart(16, "0").toUpperCase();
	const movingFactorBuffer = Buffer.from(timeHex, "hex");

	let secretBuffer: Buffer;

	if (typeof secret === "string") {
		secretBuffer = secretEncoding === "base32" ? base32Decode(secret) : Buffer.from(secret, secretEncoding);
	} else {
		secretBuffer = secret;
	}

	return generateOtp(secretBuffer, movingFactorBuffer, { ...options });
}

function generateTotpSha1(secret: Buffer, options?: TotpSpecificBufferSecretOptions): string;
function generateTotpSha1(secret: string, options?: TotpSpecificStringSecretOptions): string;
function generateTotpSha1(secret: OtpSecret, options?: TotpSpecificOptions): string {
	return generateTotp(secret, { ...options, algorithm: "sha1" });
}

function generateTotpSha256(secret: Buffer, options?: TotpSpecificBufferSecretOptions): string;
function generateTotpSha256(secret: string, options?: TotpSpecificStringSecretOptions): string;
function generateTotpSha256(secret: OtpSecret, options?: TotpSpecificOptions): string {
	return generateTotp(secret, { ...options, algorithm: "sha256" });
}

function generateTotpSha512(secret: Buffer, options?: TotpSpecificBufferSecretOptions): string;
function generateTotpSha512(secret: string, options?: TotpSpecificStringSecretOptions): string;
function generateTotpSha512(secret: OtpSecret, options?: TotpSpecificOptions): string {
	return generateTotp(secret, { ...options, algorithm: "sha512" });
}

export { generateTotp, generateTotpSha1, generateTotpSha256, generateTotpSha512 };
