import { generateTotp, generateTotpSha1 as generateTotpS } from "~/index.totp";

import type { OtpHashAlgorithm, OtpSecretStringEncoding } from "~/internal/harness.internal";

import type { TotpTestCases } from "./_harness.test";
import { generateTotpTest } from "./_harness.test";

const testCases: TotpTestCases = {
	"1234567890": [
		["1613263420", 59],
		["0393343526", 1111111109],
		["1251624539", 1111111111],
		["0843919219", 1234567890],
		["0474068722", 2000000000],
		["1772112572", 20000000000],
	],
	"12345678901234567890": [
		["1094287082", 59],
		["0907081804", 1111111109],
		["0414050471", 1111111111],
		["0689005924", 1234567890],
		["2069279037", 2000000000],
		["1465353130", 20000000000],
	],
	"12345678901234567890123456789012": [
		["0697599872", 59],
		["1482138967", 1111111109],
		["1232201283", 1111111111],
		["0023012961", 1234567890],
		["1626931087", 2000000000],
		["1903573920", 20000000000],
	],
	"1234567890123456789012345678901234567890123456789012345678901234": [
		["0214779409", 59],
		["0236110091", 1111111109],
		["0518372631", 1111111111],
		["0333973530", 1234567890],
		["0150155042", 2000000000],
		["1250487110", 20000000000],
	],
};

const algorithm: OtpHashAlgorithm = "sha1";
const secretEncoding: OtpSecretStringEncoding = "ascii";

generateTotpTest(testCases, algorithm, secretEncoding, generateTotp, generateTotpS);
