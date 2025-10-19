import { generateTotp, generateTotpSha256 as generateTotpS } from "~/index.totp";

import type { OtpHashAlgorithm, OtpSecretStringEncoding } from "~/internal/harness.internal";

import type { TotpTestCases } from "./_harness.test";
import { generateTotpTest } from "./_harness.test";

const testCases: TotpTestCases = {
	"1234567890": [
		["0980884928", 59],
		["0743659259", 1111111109],
		["0869527737", 1111111111],
		["0889350834", 1234567890],
		["1956620303", 2000000000],
		["1189326438", 20000000000],
	],
	"12345678901234567890": [
		["1332247374", 59],
		["0134756375", 1111111109],
		["0874584430", 1111111111],
		["1642829826", 1234567890],
		["0478428693", 2000000000],
		["0524142410", 20000000000],
	],
	"12345678901234567890123456789012": [
		["0746119246", 59],
		["1568084774", 1111111109],
		["1167062674", 1111111111],
		["0091819424", 1234567890],
		["1790698825", 2000000000],
		["0777737706", 20000000000],
	],
	"1234567890123456789012345678901234567890123456789012345678901234": [
		["0073786473", 59],
		["0124171431", 1111111109],
		["0993080941", 1111111111],
		["1161384964", 1234567890],
		["0513269708", 2000000000],
		["0424124209", 20000000000],
	],
};

const algorithm: OtpHashAlgorithm = "sha256";
const secretEncoding: OtpSecretStringEncoding = "ascii";

generateTotpTest(testCases, algorithm, secretEncoding, generateTotp, generateTotpS);
