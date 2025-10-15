import { describe, expect, it } from "bun:test";

import type { OtpHashAlgorithm, OtpSecretEncoding } from "../src";
import { generateTotp, generateTotpSha1, generateTotpSha256, generateTotpSha512 } from "../src";

const printCode = false;
const algorithmToTest: OtpHashAlgorithm[] = [
	//
	"sha1",
	"sha256",
	"sha512",
];
const digitsToTest: number[] = [
	//
	6,
	//
	8,
	//
	10,
	//
];

type SecretEncoding = Exclude<OtpSecretEncoding, "buffer">;
//                [6digit, 8digit,10digit, time]
type TruthTable = [string, string, string, number][];
// type Algorithm = "sha1" | "sha256" | "sha512";
type Round = [string, SecretEncoding, TruthTable, TruthTable, TruthTable];

// [secret, algorithm, [6 digit truth table], [8 digit truth table], [10 digit truth table]];
// [secret, [sha1], [sha256], [sha512]];
// Test vectors taken from https://datatracker.ietf.org/doc/html/rfc6238#autoid-17
// the actual test vectors from https://datatracker.ietf.org/doc/html/rfc6238#autoid-18 have misleading secret
const roundTest: Round[] = [
	// 1234567890 ==========================================
	[
		"1234567890",
		"ascii",
		// SHA1
		[
			["263420", "13263420", "1613263420", 59],
			["343526", "93343526", "0393343526", 1111111109],
			["624539", "51624539", "1251624539", 1111111111],
			["919219", "43919219", "0843919219", 1234567890],
			["068722", "74068722", "0474068722", 2000000000],
			["112572", "72112572", "1772112572", 20000000000],
		],
		// SHA256
		[
			["884928", "80884928", "0980884928", 59],
			["659259", "43659259", "0743659259", 1111111109],
			["527737", "69527737", "0869527737", 1111111111],
			["350834", "89350834", "0889350834", 1234567890],
			["620303", "56620303", "1956620303", 2000000000],
			["326438", "89326438", "1189326438", 20000000000],
		],
		// SHA512
		[
			["848887", "79848887", "0579848887", 59],
			["659099", "04659099", "1804659099", 1111111109],
			["074168", "32074168", "0332074168", 1111111111],
			["713642", "69713642", "0469713642", 1234567890],
			["703459", "08703459", "0708703459", 2000000000],
			["859227", "23859227", "1223859227", 20000000000],
		],
	],
	// 12345678901234567890 ==========================================
	[
		"12345678901234567890",
		"ascii",
		// SHA1
		[
			["287082", "94287082", "1094287082", 59],
			["081804", "07081804", "0907081804", 1111111109],
			["050471", "14050471", "0414050471", 1111111111],
			["005924", "89005924", "0689005924", 1234567890],
			["279037", "69279037", "2069279037", 2000000000],
			["353130", "65353130", "1465353130", 20000000000],
		],
		// SHA256
		[
			["247374", "32247374", "1332247374", 59],
			["756375", "34756375", "0134756375", 1111111109],
			["584430", "74584430", "0874584430", 1111111111],
			["829826", "42829826", "1642829826", 1234567890],
			["428693", "78428693", "0478428693", 2000000000],
			["142410", "24142410", "0524142410", 20000000000],
		],
		// SHA512
		[
			["342147", "69342147", "0369342147", 59],
			["049338", "63049338", "1763049338", 1111111109],
			["380122", "54380122", "0354380122", 1111111111],
			["671578", "76671578", "1276671578", 1234567890],
			["464532", "56464532", "1456464532", 2000000000],
			["481994", "69481994", "1069481994", 20000000000],
		],
	],
	// 12345678901234567890123456789012 ==========================================
	[
		"12345678901234567890123456789012",
		"ascii",
		// SHA1
		[
			["599872", "97599872", "0697599872", 59],
			["138967", "82138967", "1482138967", 1111111109],
			["201283", "32201283", "1232201283", 1111111111],
			["012961", "23012961", "0023012961", 1234567890],
			["931087", "26931087", "1626931087", 2000000000],
			["573920", "03573920", "1903573920", 20000000000],
		],
		// SHA256
		[
			["119246", "46119246", "0746119246", 59],
			["084774", "68084774", "1568084774", 1111111109],
			["062674", "67062674", "1167062674", 1111111111],
			["819424", "91819424", "0091819424", 1234567890],
			["698825", "90698825", "1790698825", 2000000000],
			["737706", "77737706", "0777737706", 20000000000],
		],
		// SHA512
		[
			["754366", "53754366", "0253754366", 59],
			["199770", "81199770", "0181199770", 1111111109],
			["247269", "70247269", "1570247269", 1111111111],
			["618035", "62618035", "1362618035", 1234567890],
			["046892", "11046892", "1111046892", 2000000000],
			["136826", "83136826", "1483136826", 20000000000],
		],
	],
	// 1234567890123456789012345678901234567890123456789012345678901234 ==========================================
	[
		"1234567890123456789012345678901234567890123456789012345678901234",
		"ascii",
		// SHA1
		[
			["779409", "14779409", "0214779409", 59],
			["110091", "36110091", "0236110091", 1111111109],
			["372631", "18372631", "0518372631", 1111111111],
			["973530", "33973530", "0333973530", 1234567890],
			["155042", "50155042", "0150155042", 2000000000],
			["487110", "50487110", "1250487110", 20000000000],
		],
		// SHA256
		[
			["786473", "73786473", "0073786473", 59],
			["171431", "24171431", "0124171431", 1111111109],
			["080941", "93080941", "0993080941", 1111111111],
			["384964", "61384964", "1161384964", 1234567890],
			["269708", "13269708", "0513269708", 2000000000],
			["124209", "24124209", "0424124209", 20000000000],
		],
		// SHA512
		[
			["693936", "90693936", "0490693936", 59],
			["091201", "25091201", "0225091201", 1111111109],
			["943326", "99943326", "1899943326", 1111111111],
			["441116", "93441116", "1493441116", 1234567890],
			["618901", "38618901", "1938618901", 2000000000],
			["863826", "47863826", "1047863826", 20000000000],
		],
	],
	// JBSWY3DPEHPK3PXP ==========================================
	[
		"JBSWY3DPEHPK3PXP",
		"base32",
		// SHA1
		[
			["996554", "41996554", "2041996554", 59],
			["071271", "33071271", "1733071271", 1111111109],
			["358462", "28358462", "0628358462", 1111111111],
			["742275", "94742275", "0794742275", 1234567890],
			["890699", "28890699", "0828890699", 2000000000],
			["752434", "94752434", "0594752434", 20000000000],
		],
		// SHA256
		[
			["344551", "36344551", "0436344551", 59],
			["650964", "03650964", "1703650964", 1111111109],
			["848888", "89848888", "0089848888", 1111111111],
			["488545", "32488545", "0932488545", 1234567890],
			["916370", "25916370", "0425916370", 2000000000],
			["325319", "46325319", "1346325319", 20000000000],
		],
		// SHA512
		[
			["439887", "31439887", "1031439887", 59],
			["365709", "37365709", "1037365709", 1111111109],
			["996533", "45996533", "1145996533", 1111111111],
			["136418", "03136418", "0803136418", 1234567890],
			["813052", "00813052", "1400813052", 2000000000],
			["029402", "03029402", "1603029402", 20000000000],
		],
	],
];

function generateTestDigits(
	time: number,
	six: string,
	eig: string,
	ten: string,
	otpSixArgument: string,
	otpSixSpecific: string,
	otpEigArgument: string,
	otpEigSpecific: string,
	otpTenArgument: string,
	otpTenSpecific: string,
) {
	describe(`Tim[${time.toString().padStart(12, " ")}]`, () => {
		if (digitsToTest.includes(6)) {
			it(` 6 digits [${six.padStart(12, " ")}]`, () => {
				expect(otpSixArgument).toBe(six);
				expect(otpSixSpecific).toBe(six);
			});
		}

		if (digitsToTest.includes(8)) {
			it(` 8 digits [${eig.padStart(12, " ")}]`, () => {
				expect(otpEigArgument).toBe(eig);
				expect(otpEigSpecific).toBe(eig);
			});
		}

		if (digitsToTest.includes(10)) {
			if (printCode) {
				console.log(`[${otpTenArgument}]/[${otpTenSpecific}]`);
			}

			it(`10 digits [${ten.padStart(12, " ")}]`, () => {
				expect(otpTenArgument).toBe(ten);
				expect(otpTenSpecific).toBe(ten);
			});
		}
	});
}

for (const round of roundTest) {
	const [secret, secretEncoding, ttsha1, ttsha256, ttsha512] = round;
	const secretLength = secret.length;

	let secretTitle = secret.padStart(16, " ");

	if (secretLength > 16) {
		secretTitle = [secret.slice(0, 6), ".".repeat(4), secret.slice(secretLength - 6)].join("");
	}

	describe(`Key[${secretTitle}][${secretEncoding.padStart(10, " ")}]`, () => {
		if (algorithmToTest.includes("sha1")) {
			describe("Alg[  SHA1]", () => {
				const truthTable = ttsha1;
				for (let idx = 0; idx < truthTable.length; idx += 1) {
					const currentTruthTable = truthTable[idx];
					const [six, eig, ten, time] = currentTruthTable;
					const t0 = 0;
					const interval = 30;
					const alg: OtpHashAlgorithm = "sha1";

					const digitSix = 6;
					const otpSixArgument = generateTotp(secret, secretEncoding, time, digitSix, t0, interval, alg);
					const otpSixSpecific = generateTotpSha1(secret, secretEncoding, time, digitSix, t0, interval);

					const digitEig = 8;
					const otpEigArgument = generateTotp(secret, secretEncoding, time, digitEig, t0, interval, alg);
					const otpEigSpecific = generateTotpSha1(secret, secretEncoding, time, digitEig, t0, interval);

					const digitTen = 10;
					const otpTenArgument = generateTotp(secret, secretEncoding, time, digitTen, t0, interval, alg);
					const otpTenSpecific = generateTotpSha1(secret, secretEncoding, time, digitTen, t0, interval);
					// console.log(`[${otpTenArgument}]/[${otpTenSpecific}]`);

					generateTestDigits(
						time,
						six,
						eig,
						ten,
						otpSixArgument,
						otpSixSpecific,
						otpEigArgument,
						otpEigSpecific,
						otpTenArgument,
						otpTenSpecific,
					);
				}
			});
		}

		if (algorithmToTest.includes("sha256")) {
			describe("Alg[SHA256]", () => {
				const truthTable = ttsha256;
				for (let idx = 0; idx < truthTable.length; idx += 1) {
					const currentTruthTable = truthTable[idx];
					const [six, eig, ten, time] = currentTruthTable;
					const t0 = 0;
					const interval = 30;
					const alg: OtpHashAlgorithm = "sha256";

					const digitSix = 6;
					const otpSixArgument = generateTotp(secret, secretEncoding, time, digitSix, t0, interval, alg);
					const otpSixSpecific = generateTotpSha256(secret, secretEncoding, time, digitSix, t0, interval);

					const digitEig = 8;
					const otpEigArgument = generateTotp(secret, secretEncoding, time, digitEig, t0, interval, alg);
					const otpEigSpecific = generateTotpSha256(secret, secretEncoding, time, digitEig, t0, interval);

					const digitTen = 10;
					const otpTenArgument = generateTotp(secret, secretEncoding, time, digitTen, t0, interval, alg);
					const otpTenSpecific = generateTotpSha256(secret, secretEncoding, time, digitTen, t0, interval);
					// console.log(`[${otpTenArgument}]/[${otpTenSpecific}]`);

					generateTestDigits(
						time,
						six,
						eig,
						ten,
						otpSixArgument,
						otpSixSpecific,
						otpEigArgument,
						otpEigSpecific,
						otpTenArgument,
						otpTenSpecific,
					);
				}
			});
		}

		if (algorithmToTest.includes("sha512")) {
			describe("Alg[SHA512]", () => {
				const truthTable = ttsha512;
				for (let idx = 0; idx < truthTable.length; idx += 1) {
					const currentTruthTable = truthTable[idx];
					const [six, eig, ten, time] = currentTruthTable;
					const t0 = 0;
					const interval = 30;
					const alg: OtpHashAlgorithm = "sha512";

					const digitSix = 6;
					const otpSixArgument = generateTotp(secret, secretEncoding, time, digitSix, t0, interval, alg);
					const otpSixSpecific = generateTotpSha512(secret, secretEncoding, time, digitSix, t0, interval);

					const digitEig = 8;
					const otpEigArgument = generateTotp(secret, secretEncoding, time, digitEig, t0, interval, alg);
					const otpEigSpecific = generateTotpSha512(secret, secretEncoding, time, digitEig, t0, interval);

					const digitTen = 10;
					const otpTenArgument = generateTotp(secret, secretEncoding, time, digitTen, t0, interval, alg);
					const otpTenSpecific = generateTotpSha512(secret, secretEncoding, time, digitTen, t0, interval);
					// console.log(`[${otpTenArgument}]/[${otpTenSpecific}]`);

					generateTestDigits(
						time,
						six,
						eig,
						ten,
						otpSixArgument,
						otpSixSpecific,
						otpEigArgument,
						otpEigSpecific,
						otpTenArgument,
						otpTenSpecific,
					);
				}
			});
		}
	});
}