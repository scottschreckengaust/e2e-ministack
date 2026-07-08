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
