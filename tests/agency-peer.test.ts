import { describe, expect, test } from "bun:test";

type PackageContract = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
};

const packageContract = (await Bun.file(
  new URL("../package.json", import.meta.url),
).json()) as PackageContract;

describe("Agency dependency ownership", () => {
  test("uses one host-owned Agency runtime with a tested compatibility window", () => {
    expect(
      packageContract.dependencies?.["@absolutejs/agency"],
    ).toBeUndefined();
    expect(packageContract.peerDependencies?.["@absolutejs/agency"]).toBe(
      ">=0.7.1 <0.8.0",
    );
    expect(packageContract.devDependencies?.["@absolutejs/agency"]).toBe(
      "0.7.1",
    );
    expect(packageContract.scripts?.build).toContain(
      "--external @absolutejs/agency",
    );
  });
});
