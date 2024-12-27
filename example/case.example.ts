import {
	generateTotp,
	// generateTotpSha1,
	// generateTotpSha256,
	// generateTotpSha512,
} from "../src";

const generate = [
	{
		secret: "12345678901234567890",
		algorithms: ["sha1", "sha256", "sha512"],
		digits: [6, 8, 10],
		factors: [
			0, 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000,
		],
	},
	{
		secret: "12345678901234567890123456789012",
		algorithms: ["sha1", "sha256", "sha512"],
		digits: [6, 8, 10],
		factors: [
			0, 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000,
		],
	},
	{
		secret: "1234567890123456789012345678901234567890123456789012345678901234",
		algorithms: ["sha1", "sha256", "sha512"],
		digits: [6, 8, 10],
		factors: [
			0, 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000,
		],
	},
	{
		secret:
			"1234567890123456789012345678901234567890123456789012345678901234567890",
		algorithms: ["sha1", "sha256", "sha512"],
		digits: [6, 8, 10],
		factors: [
			0, 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000,
		],
	},
];

for (const entry of generate) {
	for (const alg of entry.algorithms) {
		for (const fact of entry.factors) {
			for (const digit of entry.digits) {
				const totop = generateTotp(entry.secret, fact, digit, 0, 30, alg);
				console.log(`[${alg}][${fact}][${digit}] > [${totop}]`);
			}
		}
	}
}
