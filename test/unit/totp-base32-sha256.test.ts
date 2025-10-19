import { generateTotp, generateTotpSha256 as generateTotpS } from "~/index.totp";

import type { OtpHashAlgorithm, OtpSecretStringEncoding } from "~/internal/harness.internal";

import type { TotpTestCases } from "./_harness.test";
import { generateTotpTest } from "./_harness.test";

const testCases: TotpTestCases = {
	"JBSWY3DPEHPK3PXP": [
		["0436344551", 59],
		["1703650964", 1111111109],
		["0089848888", 1111111111],
		["0932488545", 1234567890],
		["0425916370", 2000000000],
		["1346325319", 20000000000],
	],
};

const algorithm: OtpHashAlgorithm = "sha256";
const secretEncoding: OtpSecretStringEncoding = "base32";

generateTotpTest(testCases, algorithm, secretEncoding, generateTotp, generateTotpS);
