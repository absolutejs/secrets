export type SecretOverlapRotationState = {
  currentVersion: number;
  overlapExpiresAt: number;
  previousVersion: number;
  verifiedAt?: number;
};

export type SecretOverlapDisposition =
  | "restore-previous"
  | "retain-overlap"
  | "retire-previous";

const validVersion = (version: number) =>
  Number.isSafeInteger(version) && version > 0;

export const defineSecretOverlapRotation = (input: {
  currentVersion: number;
  overlapExpiresAt: number;
  previousVersion: number;
  verifiedAt?: number;
}): SecretOverlapRotationState => {
  if (
    !validVersion(input.currentVersion) ||
    !validVersion(input.previousVersion) ||
    input.currentVersion === input.previousVersion
  )
    throw new Error(
      "Secret rotation versions must be distinct positive integers",
    );
  if (
    !Number.isSafeInteger(input.overlapExpiresAt) ||
    input.overlapExpiresAt < 0
  )
    throw new Error(
      "Secret rotation overlap expiry must be a non-negative timestamp",
    );
  if (
    input.verifiedAt !== undefined &&
    (!Number.isSafeInteger(input.verifiedAt) || input.verifiedAt < 0)
  )
    throw new Error(
      "Secret rotation verification must be a non-negative timestamp",
    );

  return { ...input };
};

export const secretOverlapCandidateVersions = (
  state: SecretOverlapRotationState,
) => [state.currentVersion, state.previousVersion] as const;

export const verifySecretOverlapVersion = (
  state: SecretOverlapRotationState,
  version: number,
  verifiedAt: number,
) =>
  version === state.currentVersion
    ? defineSecretOverlapRotation({ ...state, verifiedAt })
    : state;

export const secretOverlapDisposition = (
  state: SecretOverlapRotationState,
  at: number,
): SecretOverlapDisposition => {
  if (!Number.isSafeInteger(at) || at < 0)
    throw new Error("Secret rotation clock must be a non-negative timestamp");
  if (at < state.overlapExpiresAt) return "retain-overlap";

  return state.verifiedAt === undefined
    ? "restore-previous"
    : "retire-previous";
};
