import {
  State,
  LastUpdateStatus,
  type FunctionConfiguration,
} from '@aws-sdk/client-lambda';

/**
 * Lambda-vertical health predicate for the compatibility harness (epic #117,
 * #147). This is PER-VERTICAL — S3/DynamoDB verticals will classify their own
 * resource shapes; this one interprets a Lambda `GetFunction` response.
 *
 * `GetFunction` succeeding proves the function OBJECT exists, not that it is
 * healthy or invocable — a prior run killed mid-deploy (or a
 * `LastUpdateStatus: Failed`) can leave a half-created function. Only an
 * EXPLICIT bad state counts as unhealthy: `State: Failed`/`Inactive`, or
 * `LastUpdateStatus: Failed`. A caller that sees `false` re-provisions
 * (`cdk deploy` is idempotent, so re-running is cheap and safe).
 *
 * `Active`/`Successful` (what MiniStack returns for a healthy function) AND
 * absent/unknown fields are BOTH treated as healthy — so an emulator that omits
 * a field never defeats the verify fast-path by making it look broken.
 */
export function isFunctionConfigHealthy(
  cfg: FunctionConfiguration | undefined,
): boolean {
  const brokenState =
    cfg?.State === State.Failed || cfg?.State === State.Inactive;
  const failedUpdate = cfg?.LastUpdateStatus === LastUpdateStatus.Failed;
  return !(brokenState || failedUpdate);
}

/**
 * PROVENANCE predicate for the verify-or-provision adapter (#175).
 *
 * A `GetFunction` that succeeds proves only that SOME function of that name
 * exists — not that THIS stack provisioned it. A stale leftover, or a foreign
 * function that happens to share `compat-lambda-doubler`, would otherwise let
 * the integration oracle green without ever exercising a freshly-provisioned
 * {@link DoublerFunction}. So the adapter reads the function's `Description`
 * back and requires the EXACT marker string only that construct stamps
 * (`DOUBLER_PROVENANCE_DESCRIPTION`); this predicate is that pure check.
 *
 * Deliberately EXACT-match and marker-passed-in: the expected value lives in
 * the construct (the single source of truth for what gets stamped) and is
 * threaded through here, so `health.ts` stays free of any CDK import. An
 * absent/empty/foreign Description is `false` (fail loudly / re-provision); only
 * the exact marker is `true`.
 */
export function hasProvenanceMarker(
  cfg: FunctionConfiguration | undefined,
  expectedDescription: string,
): boolean {
  return cfg?.Description === expectedDescription;
}
