import type { HeadBucketCommandOutput } from '@aws-sdk/client-s3';

/**
 * S3-vertical health predicate for the compatibility harness (epic #117, #139).
 * This is PER-VERTICAL — the Lambda vertical classifies a `GetFunction`
 * response; this one interprets a `HeadBucket` response.
 *
 * `HeadBucket` succeeding proves the bucket OBJECT exists and is reachable, but
 * a caller that talks to a misbehaving endpoint could still get a 2xx-shaped
 * envelope carrying a non-success HTTP status. Only an EXPLICIT bad status
 * counts as unhealthy: a present `$metadata.httpStatusCode` outside the 2xx
 * range. A caller that sees `false` re-provisions (`cdk deploy` is idempotent,
 * so re-running is cheap and safe).
 *
 * A `2xx` status (what MiniStack returns for a healthy bucket) AND an
 * absent/unknown status are BOTH treated as healthy — so an emulator that omits
 * the field never defeats the verify fast-path by making it look broken.
 * (A genuinely missing bucket surfaces as a thrown `NotFound`/`NoSuchBucket` at
 * the call site, not as a response this predicate ever sees.)
 */
export function isBucketHeadHealthy(
  res: HeadBucketCommandOutput | undefined,
): boolean {
  const status = res?.$metadata?.httpStatusCode;
  if (status === undefined) return true;
  return status >= 200 && status < 300;
}
