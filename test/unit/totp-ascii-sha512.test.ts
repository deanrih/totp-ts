import { generateTotp, generateTotpSha512 as generateTotpS } from "~/index.totp";

import type { OtpHashAlgorithm, OtpSecretStringEncoding } from "~/internal/harness.internal";

import type { TotpTestCases } from "./_harness.test";
import { generateTotpTest } from "./_harness.test";

const testCases: TotpTestCases = {
	"1234567890": [
		["0579848887", 59],
		["1804659099", 1111111109],
		["0332074168", 1111111111],
		["0469713642", 1234567890],
		["0708703459", 2000000000],
		["1223859227", 20000000000],
	],
	"12345678901234567890": [
		["0369342147", 59],
		["1763049338", 1111111109],
		["0354380122", 1111111111],
		["1276671578", 1234567890],
		["1456464532", 2000000000],
		["1069481994", 20000000000],
	],
	"12345678901234567890123456789012": [
		["0253754366", 59],
		["0181199770", 1111111109],
		["1570247269", 1111111111],
		["1362618035", 1234567890],
		["1111046892", 2000000000],
		["1483136826", 20000000000],
	],
	"1234567890123456789012345678901234567890123456789012345678901234": [
		["0490693936", 59],
		["0225091201", 1111111109],
		["1899943326", 1111111111],
		["1493441116", 1234567890],
		["1938618901", 2000000000],
		["1047863826", 20000000000],
	],
};

const algorithm: OtpHashAlgorithm = "sha512";
const secretEncoding: OtpSecretStringEncoding = "ascii";

generateTotpTest(testCases, algorithm, secretEncoding, generateTotp, generateTotpS);
