import type { HeadBucketCommandOutput } from '@aws-sdk/client-s3';
import { isBucketHeadHealthy } from '../../../services/s3/health';

// Unit test for the S3-vertical health predicate (#139). Table-drives every
// branch of the HeadBucket HTTP-status classifier so the module is held at the
// repo's 100% gate: the undefined-response and absent-status tolerance branches,
// the 2xx-healthy band, and the explicit non-2xx (low and high) unhealthy cases.
describe('isBucketHeadHealthy', () => {
  // A HeadBucketCommandOutput is $metadata + optional fields; only the HTTP
  // status matters here. Cast a minimal shape rather than the full type.
  const withStatus = (
    httpStatusCode: number | undefined,
  ): HeadBucketCommandOutput =>
    ({ $metadata: { httpStatusCode } }) as HeadBucketCommandOutput;

  const cases: Array<[string, HeadBucketCommandOutput | undefined, boolean]> = [
    ['undefined response → healthy (tolerated)', undefined, true],
    // No $metadata at all: exercises the `$metadata?.` short-circuit branch.
    [
      'absent $metadata → healthy (tolerated)',
      {} as HeadBucketCommandOutput,
      true,
    ],
    [
      'absent httpStatusCode → healthy (tolerated)',
      withStatus(undefined),
      true,
    ],
    ['200 → healthy', withStatus(200), true],
    ['299 (top of 2xx) → healthy', withStatus(299), true],
    ['199 (just below 2xx) → unhealthy', withStatus(199), false],
    ['300 (just above 2xx) → unhealthy', withStatus(300), false],
    ['403 → unhealthy', withStatus(403), false],
    ['500 → unhealthy', withStatus(500), false],
  ];

  it.each(cases)('%s', (_label, res, expected) => {
    expect(isBucketHeadHealthy(res)).toBe(expected);
  });
});
