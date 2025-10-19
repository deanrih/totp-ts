import { generateHotp, generateHotpSha1 as generateHotpS } from "~/index.hotp";

import type { OtpHashAlgorithm, OtpSecretStringEncoding } from "~/internal/harness.internal";

import type { HotpTestCases } from "./_harness.test";
import { generateHotpTest } from "./_harness.test";

const rounds: HotpTestCases = {
	"12345678901234567890": [
		"1284755224",
		"1094287082",
		"0137359152",
		"1726969429",
		"1640338314",
		"0868254676",
		"1918287922",
		"0082162583",
		"0673399871",
		"0645520489",
	],
};

const algorithm: OtpHashAlgorithm = "sha1";
const secretEncoding: OtpSecretStringEncoding = "ascii";

generateHotpTest(rounds, algorithm, secretEncoding, generateHotp, generateHotpS);
