import { describe, expect, it } from "bun:test";

import type { OtpHashAlgorithm, OtpSecretStringEncoding } from "~/internal/harness.internal";
import type { generateHotp, generateHotpSha1, generateHotpSha256, generateHotpSha512 } from "~/index.hotp";
import type { generateTotp, generateTotpSha1, generateTotpSha256, generateTotpSha512 } from "~/index.totp";

import { otpDigitLength } from "~/internal/harness.internal";

type GeneratorGeneralHotp = typeof generateHotp;
type GeneratorGeneralTotp = typeof generateTotp;

type GeneratorSpecificHotp = typeof generateHotpSha1 | typeof generateHotpSha256 | typeof generateHotpSha512;
type GeneratorSpecificTotp = typeof generateTotpSha1 | typeof generateTotpSha256 | typeof generateTotpSha512;

interface TotpTestCases {
	[key: string]: [string, number][];
}
interface HotpTestCases {
	[key: string]: string[];
}
interface TotpTestOptions {
	t0?: number;
	interval?: number;
}

function generateTestTitle(title: string, maxLength: number = 16, separatorLength: number = 4) {
	const length = title.length;
	const separatorTotalLength = Math.ceil(separatorLength / 2);
	const targetHalfLength = Math.ceil(maxLength / 2) - 2;

	let finalTitle = title.padStart(maxLength, " ");

	if (length > maxLength) {
		finalTitle = [
			title.slice(0, targetHalfLength),
			".".repeat(separatorTotalLength),
			title.slice(length - targetHalfLength),
		].join("");
	}

	return finalTitle;
}

function generateHotpTest(
	testCases: HotpTestCases,
	algorithm: OtpHashAlgorithm,
	secretEncoding: OtpSecretStringEncoding,
	generatorGeneral: GeneratorGeneralHotp,
	generatorSpecific: GeneratorSpecificHotp,
) {
	for (const secret in testCases) {
		const title = generateTestTitle(secret);

		describe(`hotp/${algorithm}/${secretEncoding.padStart(10, " ")}/${title}`, () => {
			const groundTruth = testCases[secret];

			for (let idx = 0; idx < groundTruth.length; idx += 1) {
				const code = groundTruth[idx];

				it(`${idx.toString().padStart(3, " ")}`, () => {
					for (const digits of otpDigitLength) {
						const sliceIdx = 10 - digits;
						const expected = code.slice(sliceIdx);

						const general = generatorGeneral(secret, idx, { algorithm, digits, secretEncoding });
						const specific = generatorSpecific(secret, idx, { digits, secretEncoding });

						expect(general).toBe(expected);
						expect(specific).toBe(expected);
					}
				});
			}
		});
	}
}

function generateTotpTest(
	testCases: TotpTestCases,
	algorithm: OtpHashAlgorithm,
	secretEncoding: OtpSecretStringEncoding,
	generatorGeneral: GeneratorGeneralTotp,
	generatorSpecific: GeneratorSpecificTotp,
	options?: TotpTestOptions,
) {
	const t0 = options?.t0 ?? 0;
	const interval = options?.interval ?? 30;

	for (const secret in testCases) {
		const title = generateTestTitle(secret);

		describe(`totp/${algorithm}/${secretEncoding.padStart(10, " ")}/${title}`, () => {
			const groundTruth = testCases[secret];

			for (let idx = 0; idx < groundTruth.length; idx += 1) {
				const [code, time] = groundTruth[idx];

				it(`${time.toString().padStart(12, " ")}`, () => {
					for (const digits of otpDigitLength) {
						const sliceIdx = 10 - digits;
						const expected = code.slice(sliceIdx);

						const general = generatorGeneral(secret, { algorithm, digits, secretEncoding, interval, t0, time });
						const specific = generatorSpecific(secret, { digits, secretEncoding, interval, t0, time });

						expect(general).toBe(expected);
						expect(specific).toBe(expected);
					}
				});
			}
		});
	}
}

export { generateHotpTest, generateTotpTest };
export type { HotpTestCases, TotpTestCases };
