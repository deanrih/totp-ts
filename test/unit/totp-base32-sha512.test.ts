import { generateTotp, generateTotpSha512 as generateTotpS } from "~/index.totp";

import type { OtpHashAlgorithm, OtpSecretStringEncoding } from "~/internal/harness.internal";

import type { TotpTestCases } from "./_harness.test";
import { generateTotpTest } from "./_harness.test";

const testCases: TotpTestCases = {
	"JBSWY3DPEHPK3PXP": [
		["1031439887", 59],
		["1037365709", 1111111109],
		["1145996533", 1111111111],
		["0803136418", 1234567890],
		["1400813052", 2000000000],
		["1603029402", 20000000000],
	],
};

const algorithm: OtpHashAlgorithm = "sha512";
const secretEncoding: OtpSecretStringEncoding = "base32";

generateTotpTest(testCases, algorithm, secretEncoding, generateTotp, generateTotpS);
