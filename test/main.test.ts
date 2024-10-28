import { describe, expect, it } from "bun:test";

import {
	generateTotp,
	generateTotpSha1,
	generateTotpSha256,
	generateTotpSha512,
} from "../src/main";

// Test vectors taken from https://datatracker.ietf.org/doc/html/rfc6238#autoid-17
// the actual test vectors from https://datatracker.ietf.org/doc/html/rfc6238#autoid-18 have misleading secret
const rounds = [
	{
		algorithm: "sha1",
		digit: 8,
		secret: "12345678901234567890",
		cases: [
			{ time: 59, totp: "94287082" },
			{ time: 1111111109, totp: "07081804" },
			{ time: 1111111111, totp: "14050471" },
			{ time: 1234567890, totp: "89005924" },
			{ time: 2000000000, totp: "69279037" },
			{ time: 20000000000, totp: "65353130" },
		],
	},
	{
		algorithm: "sha256",
		digit: 8,
		secret: "12345678901234567890123456789012",
		cases: [
			{ time: 59, totp: "46119246" },
			{ time: 1111111109, totp: "68084774" },
			{ time: 1111111111, totp: "67062674" },
			{ time: 1234567890, totp: "91819424" },
			{ time: 2000000000, totp: "90698825" },
			{ time: 20000000000, totp: "77737706" },
		],
	},
	{
		algorithm: "sha512",
		digit: 8,
		secret: "1234567890123456789012345678901234567890123456789012345678901234",
		cases: [
			{ time: 59, totp: "90693936" },
			{ time: 1111111109, totp: "25091201" },
			{ time: 1111111111, totp: "99943326" },
			{ time: 1234567890, totp: "93441116" },
			{ time: 2000000000, totp: "38618901" },
			{ time: 20000000000, totp: "47863826" },
		],
	},
];

for (const { algorithm, cases, digit, secret } of rounds) {
	describe(`[${" ".repeat(6 - algorithm.length) + algorithm}]; [${secret.length > 16 ? `...${secret.substring(secret.length - 13)}` : " ".repeat(16 - secret.length) + secret}];`, () => {
		for (const { time, totp } of cases) {
			it(`[${String(time).length < 12 ? " ".repeat(12 - String(time).length) + time : time}] === [${totp}]`, () => {
				expect(generateTotp(secret, time, digit, 0, 30, algorithm)).toBe(totp);
			});
			if (algorithm === "sha1") {
				it(`[${String(time).length < 12 ? " ".repeat(12 - String(time).length) + time : time}] === [${totp}]; [SPECIFIC]`, () => {
					expect(generateTotpSha1(secret, time, digit, 0, 30)).toBe(totp);
				});
			} else if (algorithm === "sha256") {
				it(`[${String(time).length < 12 ? " ".repeat(12 - String(time).length) + time : time}] === [${totp}]; [SPECIFIC]`, () => {
					expect(generateTotpSha256(secret, time, digit, 0, 30)).toBe(totp);
				});
			} else if (algorithm === "sha512") {
				it(`[${String(time).length < 12 ? " ".repeat(12 - String(time).length) + time : time}] === [${totp}]; [SPECIFIC]`, () => {
					expect(generateTotpSha512(secret, time, digit, 0, 30)).toBe(totp);
				});
			}
		}
	});
}
