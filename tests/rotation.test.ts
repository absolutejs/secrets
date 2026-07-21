import { describe, expect, test } from "bun:test";
import {
  defineSecretOverlapRotation,
  secretOverlapCandidateVersions,
  secretOverlapDisposition,
  verifySecretOverlapVersion,
} from "../src/rotation";

describe("versioned secret overlap rotation", () => {
  test("tries the current version first and ignores proof from the previous version", () => {
    const state = defineSecretOverlapRotation({
      currentVersion: 2,
      overlapExpiresAt: 20,
      previousVersion: 1,
    });

    expect(secretOverlapCandidateVersions(state)).toEqual([2, 1]);
    expect(verifySecretOverlapVersion(state, 1, 10)).toEqual(state);
    expect(secretOverlapDisposition(state, 19)).toBe("retain-overlap");
  });

  test("retires a proven prior version when the overlap expires", () => {
    const verified = verifySecretOverlapVersion(
      defineSecretOverlapRotation({
        currentVersion: 2,
        overlapExpiresAt: 20,
        previousVersion: 1,
      }),
      2,
      10,
    );

    expect(secretOverlapDisposition(verified, 20)).toBe("retire-previous");
  });

  test("restores the known-good version when the replacement is not proven", () => {
    const state = defineSecretOverlapRotation({
      currentVersion: 2,
      overlapExpiresAt: 20,
      previousVersion: 1,
    });

    expect(secretOverlapDisposition(state, 20)).toBe("restore-previous");
  });
});
