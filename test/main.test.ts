import { describe, expect, it } from "bun:test";

import {
	generateTotp,
	generateTotpSha1,
	generateTotpSha256,
	generateTotpSha512,
} from "../src";

// Test vectors taken from https://datatracker.ietf.org/doc/html/rfc6238#autoid-17
// the actual test vectors from https://datatracker.ietf.org/doc/html/rfc6238#autoid-18 have misleading secret
const rounds = [
	{
		algorithm: "sha1",
		secret: "12345678901234567890",
		cases: [
			{ digit: 8, time: 59, totp: "94287082" },
			{ digit: 8, time: 1111111109, totp: "07081804" },
			{ digit: 8, time: 1111111111, totp: "14050471" },
			{ digit: 8, time: 1234567890, totp: "89005924" },
			{ digit: 8, time: 2000000000, totp: "69279037" },
			{ digit: 8, time: 20000000000, totp: "65353130" },

			{ digit: 10, time: 59, totp: "1094287082" },
			{ digit: 10, time: 1111111109, totp: "0907081804" },
			{ digit: 10, time: 1111111111, totp: "0414050471" },
			{ digit: 10, time: 1234567890, totp: "0689005924" },
			{ digit: 10, time: 2000000000, totp: "2069279037" },
			{ digit: 10, time: 20000000000, totp: "1465353130" },
		],
	},
	{
		algorithm: "sha256",
		secret: "12345678901234567890123456789012",
		cases: [
			{ digit: 8, time: 59, totp: "46119246" },
			{ digit: 8, time: 1111111109, totp: "68084774" },
			{ digit: 8, time: 1111111111, totp: "67062674" },
			{ digit: 8, time: 1234567890, totp: "91819424" },
			{ digit: 8, time: 2000000000, totp: "90698825" },
			{ digit: 8, time: 20000000000, totp: "77737706" },

			{ digit: 10, time: 59, totp: "0746119246" },
			{ digit: 10, time: 1111111109, totp: "1568084774" },
			{ digit: 10, time: 1111111111, totp: "1167062674" },
			{ digit: 10, time: 1234567890, totp: "0091819424" },
			{ digit: 10, time: 2000000000, totp: "1790698825" },
			{ digit: 10, time: 20000000000, totp: "0777737706" },
		],
	},
	{
		algorithm: "sha512",
		secret: "1234567890123456789012345678901234567890123456789012345678901234",
		cases: [
			{ digit: 8, time: 59, totp: "90693936" },
			{ digit: 8, time: 1111111109, totp: "25091201" },
			{ digit: 8, time: 1111111111, totp: "99943326" },
			{ digit: 8, time: 1234567890, totp: "93441116" },
			{ digit: 8, time: 2000000000, totp: "38618901" },
			{ digit: 8, time: 20000000000, totp: "47863826" },

			{ digit: 10, time: 59, totp: "0490693936" },
			{ digit: 10, time: 1111111109, totp: "0225091201" },
			{ digit: 10, time: 1111111111, totp: "1899943326" },
			{ digit: 10, time: 1234567890, totp: "1493441116" },
			{ digit: 10, time: 2000000000, totp: "1938618901" },
			{ digit: 10, time: 20000000000, totp: "1047863826" },
		],
	},
];

const allDigits = rounds.flatMap((x) => x.cases.map((x) => x.digit));
const maxDigits = Math.max(...allDigits);

const pad = " ".repeat(2);
const alg = `${" ".repeat(3)}alg`;
const sec = `${" ".repeat(2)}secret`;
const mvf = `${" ".repeat(8)}factor`;
const dig = `${" ".repeat(0)}dig`;
const exp = `${" ".repeat(maxDigits - 8)}expected`;
console.log(
	`${pad}${alg}/${sec} > ${dig} / ${mvf} = ${exp} / specific function call`,
);

for (const { algorithm, cases, secret } of rounds) {
	describe(`${" ".repeat(6 - algorithm.length) + algorithm}/${secret.length > 8 ? `...${secret.substring(secret.length - 5)}` : " ".repeat(8 - secret.length) + secret}`, () => {
		for (const { digit, time, totp } of cases) {
			const timeStirngLen = String(time).length;
			const digitStringLen = String(digit).length;

			it(`${" ".repeat(3 - digitStringLen) + digit} / [${timeStirngLen < 12 ? " ".repeat(12 - timeStirngLen) + time : time}] = ${" ".repeat(maxDigits - totp.length) + totp}`, () => {
				expect(generateTotp(secret, time, digit, 0, 30, algorithm)).toBe(totp);
			});
			if (algorithm === "sha1") {
				it(`${" ".repeat(3 - digitStringLen) + digit} / [${timeStirngLen < 12 ? " ".repeat(12 - timeStirngLen) + time : time}] = ${" ".repeat(maxDigits - totp.length) + totp} / SPECIFIC`, () => {
					expect(generateTotpSha1(secret, time, digit, 0, 30)).toBe(totp);
				});
			} else if (algorithm === "sha256") {
				it(`${" ".repeat(3 - digitStringLen) + digit} / [${timeStirngLen < 12 ? " ".repeat(12 - timeStirngLen) + time : time}] = ${" ".repeat(maxDigits - totp.length) + totp} / SPECIFIC`, () => {
					expect(generateTotpSha256(secret, time, digit, 0, 30)).toBe(totp);
				});
			} else if (algorithm === "sha512") {
				it(`${" ".repeat(3 - digitStringLen) + digit} / [${timeStirngLen < 12 ? " ".repeat(12 - timeStirngLen) + time : time}] = ${" ".repeat(maxDigits - totp.length) + totp} / SPECIFIC`, () => {
					expect(generateTotpSha512(secret, time, digit, 0, 30)).toBe(totp);
				});
			}
		}
	});
}
