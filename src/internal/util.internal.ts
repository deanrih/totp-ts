import type { OtpType, OtpHashAlgorithm, OtpDigitLength } from "./harness.internal";
import { otpDigitLength, unreasonableDigitError } from "./harness.internal";

interface OtpUriOptions {
	algorithm: OtpHashAlgorithm;
	digits: OtpDigitLength;
	counter: number;
	period: number;
}

interface HotpUriOptions extends Partial<Omit<OtpUriOptions, "period">> {}
interface TotpUriOptions extends Partial<Omit<OtpUriOptions, "counter">> {}

function setUriEncodedMap(map: Map<string, string>, key: string, val: string) {
	const encode = encodeURI;

	key = encode(key);
	val = encode(val);

	map.set(key, val);
}

function mapToParams(map: Map<string, string>): string {
	const result: string[] = [];

	for (const [key, val] of map.entries()) {
		result.push(`${key}=${val}`);
	}

	return result.join("&");
}

function generateOtpUri(type: "hotp", issuer: string, subject: string, secret: string, options?: HotpUriOptions): string;
function generateOtpUri(type: "totp", issuer: string, subject: string, secret: string, options?: TotpUriOptions): string;
function generateOtpUri(
	type: OtpType,
	issuer: string,
	subject: string,
	secret: string,
	options?: HotpUriOptions | TotpUriOptions,
): string;
function generateOtpUri(
	type: OtpType,
	issuer: string,
	subject: string,
	secret: string,
	options?: HotpUriOptions | TotpUriOptions,
): string {
	const algorithm = options?.algorithm ?? "sha1";
	const digits = options?.digits ?? 6;
	const counter = (<HotpUriOptions>options)?.counter ?? 0;
	const period = (<TotpUriOptions>options)?.period ?? 30;

	if (!otpDigitLength.includes(digits)) {
		throw unreasonableDigitError;
	}

	const encode = encodeURI;

	const protocol = "otpauth:";
	const label = [encode(issuer), ":", encode(subject)].join("");

	const paramsMap = new Map<string, string>();
	setUriEncodedMap(paramsMap, "secret", secret);
	setUriEncodedMap(paramsMap, "issuer", issuer);
	setUriEncodedMap(paramsMap, "algorithm", algorithm);
	setUriEncodedMap(paramsMap, "digits", digits.toString());
	setUriEncodedMap(paramsMap, type === "hotp" ? "counter" : "period", type === "hotp" ? counter.toString() : period.toString());
	const params = mapToParams(paramsMap);
	const uri = new URL(`${protocol}//${type}/${label}?${params}`);

	return uri.href;
}

function generateHotpUri(issuer: string, subject: string, secret: string, options?: HotpUriOptions): string {
	return generateOtpUri("hotp", issuer, subject, secret, options);
}
function generateTotpUri(issuer: string, subject: string, secret: string, options?: TotpUriOptions): string {
	return generateOtpUri("totp", issuer, subject, secret, options);
}

export { generateOtpUri, generateHotpUri, generateTotpUri };
