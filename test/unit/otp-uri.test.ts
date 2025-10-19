import { describe, expect, it } from "bun:test";

import type { OtpDigitLength, OtpHashAlgorithm, OtpType } from "~/internal/harness.internal";
import { generateHotpUri, generateOtpUri, generateTotpUri } from "~/index.util";

type Rounds = [
	type: OtpType,
	issuer: string,
	subject: string,
	secret: string,
	algorithm: OtpHashAlgorithm,
	digits: OtpDigitLength,
	counterPeriod: number,
	expected: string,
];
const rounds: Rounds[] = [
	[
		"totp",
		"ACME Co",
		"john.doe@email.com",
		"HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
		"sha1",
		6,
		30,
		"otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=sha1&digits=6&period=30",
	],
	[
		"totp",
		"Example",
		"alice@google.com",
		"JBSWY3DPEHPK3PXP",
		"sha1",
		6,
		30,
		"otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha1&digits=6&period=30",
	],
];

for (const round of rounds) {
	const [type, issuer, subject, secret, algorithm, digits, counterPeriod, expected] = round;

	describe("otp-uri generation", () => {
		it("matches", () => {
			const result = generateOtpUri(type, issuer, subject, secret, {
				algorithm,
				counter: counterPeriod,
				digits,
				period: counterPeriod,
			});

			expect(result).toBe(expected);

			if (type === "hotp") {
				expect(generateHotpUri(issuer, subject, secret, { algorithm, counter: counterPeriod, digits }));
			} else if (type === "totp") {
				expect(generateTotpUri(issuer, subject, secret, { algorithm, period: counterPeriod, digits }));
			}
		});
	});
}
