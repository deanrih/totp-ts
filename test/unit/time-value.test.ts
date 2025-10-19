import { describe, expect, it } from "bun:test";

import { numberToBytes } from "~/internal/harness.internal";

const t0 = 0;
const interval = 30;

const rounds = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000];

function calculateBufferLegacyGroundTruth(value: number): Buffer {
	const timeHex = value.toString(16).padStart(16, "0").toUpperCase();
	const timeBuffer = Buffer.from(timeHex, "hex");

	return timeBuffer;
}

for (const round of rounds) {
	const timeInput = round % 1 !== 0 ? round | 0 : round;
	const timeFactor = ((timeInput - t0) / interval) | 0;
	const timeFloored = Math.floor(timeFactor);

	const groundTruth = calculateBufferLegacyGroundTruth(timeFloored);

	describe("moving-factor buffer calculation", () => {
		it(`${round.toString().padStart(12, " ")}/${timeFloored.toString().padStart(10, " ")}/${Bun.inspect(groundTruth)}`, () => {
			const buffer = numberToBytes(timeFloored);
			expect(buffer).toEqual(groundTruth);
		});
	});
}
