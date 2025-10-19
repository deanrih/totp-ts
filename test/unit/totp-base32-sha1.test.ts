import { generateTotp, generateTotpSha1 as generateTotpS } from "~/index.totp";

import type { OtpHashAlgorithm, OtpSecretStringEncoding } from "~/internal/harness.internal";

import type { TotpTestCases } from "./_harness.test";
import { generateTotpTest } from "./_harness.test";

const testCases: TotpTestCases = {
	"JBSWY3DPEHPK3PXP": [
		["2041996554", 59],
		["1733071271", 1111111109],
		["0628358462", 1111111111],
		["0794742275", 1234567890],
		["0828890699", 2000000000],
		["0594752434", 20000000000],
	],
};

const algorithm: OtpHashAlgorithm = "sha1";
const secretEncoding: OtpSecretStringEncoding = "base32";

generateTotpTest(testCases, algorithm, secretEncoding, generateTotp, generateTotpS);
